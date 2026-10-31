"""Verification engine: deterministic proof that a fix actually worked.

The status of a verification is decided exclusively from scanner/database
evidence — a completed scan, the package version it observed, and whether the
finding survived. AI may explain the outcome afterwards; it cannot change it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    AIExecutionKind,
    RemediationStatus,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.providers.registry import get_provider
from app.modules.ai.services.executions import record_result, track_execution
from app.modules.findings.models import Finding
from app.modules.remediation import service as remediation_service
from app.modules.remediation.models import RemediationRecommendation
from app.modules.sbom.models import Sbom, SbomPackage
from app.modules.scans.models import Scan
from app.modules.security_intelligence.versions import explain_comparison, safe_compare
from app.modules.security_policies import service as policies_service
from app.modules.verification.models import RemediationVerification

logger = get_logger(__name__)


# ------------------------------------------------------------------ triggering
def request_verification(
    db: Session, recommendation_id: uuid.UUID, *, actor: str = "api"
) -> tuple[RemediationRecommendation, Scan]:
    """Move a recommendation to VALIDATING and start a fresh scan."""
    from app.modules.assets.models import Asset
    from app.modules.scans import service as scans_service

    recommendation = remediation_service.get_or_404(db, recommendation_id)
    if recommendation.status not in {
        RemediationStatus.APPROVED.value,
        RemediationStatus.VALIDATING.value,
        RemediationStatus.VERIFIED.value,
    }:
        raise ConflictError(
            "Only an approved recommendation can be verified",
            details={"status": recommendation.status},
        )
    asset = db.get(Asset, recommendation.asset_id)
    if asset is None:
        raise NotFoundError("Asset not found", details={"asset_id": str(recommendation.asset_id)})

    if recommendation.status == RemediationStatus.APPROVED.value:
        remediation_service.transition(
            db,
            recommendation,
            RemediationStatus.VALIDATING.value,
            actor=actor,
            note="Verification scan requested.",
        )
    scan = scans_service.create_scan(db, asset, requested_by=actor)
    db.commit()
    logger.info(
        "verification scan requested",
        extra={
            "extra_fields": {
                "recommendation_id": str(recommendation.id),
                "scan_id": str(scan.id),
                "asset_id": str(asset.id),
            }
        },
    )
    return recommendation, scan


# ----------------------------------------------------------------- evaluation
def on_scan_completed(db: Session, scan_id: uuid.UUID) -> list[RemediationVerification]:
    """Evaluate every open recommendation for the scan's asset.

    Called by the scan pipeline after a successful scan: verification is a
    reaction to real evidence, never a scheduled guess.
    """
    scan = db.get(Scan, scan_id)
    if scan is None or scan.status != ScanStatus.COMPLETED.value:
        return []
    recommendations = list(
        db.execute(
            select(RemediationRecommendation).where(
                RemediationRecommendation.asset_id == scan.asset_id,
                RemediationRecommendation.status.in_(
                    [RemediationStatus.VALIDATING.value, RemediationStatus.APPROVED.value]
                ),
            )
        ).scalars()
    )
    results = []
    for recommendation in recommendations:
        verification = evaluate(db, recommendation, scan)
        if verification is not None:
            results.append(verification)
    if results:
        db.commit()
    return results


def evaluate(
    db: Session, recommendation: RemediationRecommendation, scan: Scan
) -> RemediationVerification | None:
    finding = db.get(Finding, recommendation.finding_id)
    if finding is None:
        return None
    policy_row = policies_service.active_policy(db, "REMEDIATION")
    policy = {
        **policies_service.DEFAULT_REMEDIATION_POLICY,
        **((policy_row.config if policy_row else {}) or {}),
    }
    max_new_high = int(policy.get("max_new_high_findings", 0))

    versions_after = _package_versions_in_scan(
        db, scan_id=scan.id, package_name=recommendation.target_package
    )
    before_version = recommendation.current_version or finding.package_version
    after_version = _select_after_version(
        versions=versions_after,
        before_version=before_version,
        recommended_version=recommendation.recommended_version,
    )
    package_present = bool(versions_after)

    finding_present_after = bool(
        finding.status in {"OPEN", "CONFIRMED", "ACCEPTED_RISK"} and finding.last_scan_id == scan.id
    )
    new_high = int(
        db.execute(
            select(Finding.id).where(
                Finding.first_scan_id == scan.id,
                Finding.severity.in_([Severity.CRITICAL.value, Severity.HIGH.value]),
            )
        )
        .scalars()
        .all()
        .__len__()
    )

    status = _decide_status(
        finding_present_after=finding_present_after,
        before_version=before_version,
        after_version=after_version,
        package_present=package_present,
        new_high=new_high,
        max_new_high=max_new_high,
        scan=scan,
    )

    verification = RemediationVerification(
        recommendation_id=recommendation.id,
        finding_id=finding.id,
        asset_id=recommendation.asset_id,
        original_scan_id=finding.last_scan_id if finding.last_scan_id != scan.id else None,
        verification_scan_id=scan.id,
        status=status,
        before_version=before_version,
        after_version=after_version,
        finding_present_after=finding_present_after,
        package_present_after=package_present,
        new_findings_count=new_high,
        policy_result={
            "max_new_high_findings": max_new_high,
            "new_high_findings": new_high,
            "policy_key": policy_row.key if policy_row else "default-remediation",
        },
        evidence={
            "scan_id": str(scan.id),
            "scan_status": scan.status,
            "commit_sha": scan.commit_sha,
            "finding_fingerprint": finding.fingerprint,
            "finding_status": finding.status,
            "finding_last_scan_id": str(finding.last_scan_id) if finding.last_scan_id else None,
            "before_version": before_version,
            "after_version": after_version,
            "package_versions_after": versions_after,
            "package_present_after": package_present,
            "version_comparison": explain_comparison(
                str(after_version or ""), str(before_version or ""), None
            )
            if after_version and before_version
            else "unknown",
            "scanner_failures": scan.error_message if scan.status != ScanStatus.COMPLETED.value else None,
        },
        notes=_note_for(status),
        verified_at=datetime.now(UTC),
    )
    db.add(verification)
    db.flush()

    # An externally-triggered scan can arrive while the recommendation is still
    # APPROVED; normalise the state before recording the outcome.
    if recommendation.status == RemediationStatus.APPROVED.value:
        remediation_service.transition(
            db,
            recommendation,
            RemediationStatus.VALIDATING.value,
            actor="verification",
            note=f"Verification scan {scan.id} completed.",
        )

    # The lifecycle follows the deterministic outcome, not a model.
    if status == VerificationStatus.VERIFIED_FIXED.value:
        remediation_service.transition(
            db,
            recommendation,
            RemediationStatus.VERIFIED.value,
            actor="verification",
            note=f"Verified by scan {scan.id}.",
        )
    elif status in {
        VerificationStatus.STILL_VULNERABLE.value,
        VerificationStatus.PARTIALLY_FIXED.value,
        VerificationStatus.NEW_RISK_INTRODUCED.value,
        VerificationStatus.VERIFICATION_FAILED.value,
    }:
        remediation_service.transition(
            db,
            recommendation,
            RemediationStatus.FAILED.value,
            actor="verification",
            note=_note_for(status),
        )
    logger.info(
        "verification evaluated",
        extra={
            "extra_fields": {
                "verification_id": str(verification.id),
                "recommendation_id": str(recommendation.id),
                "status": status,
                "before": before_version,
                "after": after_version,
                "new_high": new_high,
            }
        },
    )
    return verification


def _package_versions_in_scan(
    db: Session, *, scan_id: uuid.UUID, package_name: str | None
) -> list[str]:
    """Every version of the package observed by the verification scan.

    A repository can legitimately contain several copies of one package
    (node_modules trees do this), so "the version after the fix" is a set, never
    a single arbitrary row.
    """
    if not package_name:
        return []
    rows = db.execute(
        select(SbomPackage.version)
        .join(Sbom, Sbom.id == SbomPackage.sbom_id)
        .where(Sbom.scan_id == scan_id, SbomPackage.name == package_name)
    ).scalars().all()
    return sorted({version for version in rows if version})


def _select_after_version(
    *, versions: list[str], before_version: str | None, recommended_version: str | None
) -> str | None:
    """Pick the version that represents the outcome, deterministically.

    Order of preference: the old version is still present (nothing changed) → the
    recommended version is present (the fix landed) → the highest version found.
    """
    if not versions:
        return None
    if before_version and before_version in versions:
        return before_version
    if recommended_version and recommended_version in versions:
        return recommended_version
    best = versions[0]
    for candidate in versions[1:]:
        comparison = safe_compare(candidate, best)
        if comparison is not None and comparison > 0:
            best = candidate
    return best


def _decide_status(
    *,
    finding_present_after: bool,
    before_version: str | None,
    after_version: str | None,
    package_present: bool,
    new_high: int,
    max_new_high: int,
    scan: Scan,
) -> str:
    if scan.status != ScanStatus.COMPLETED.value:
        return VerificationStatus.VERIFICATION_FAILED.value
    introduced = new_high > max_new_high
    version_changed = bool(before_version and after_version and after_version != before_version)
    if finding_present_after and not version_changed:
        return VerificationStatus.STILL_VULNERABLE.value
    if finding_present_after and version_changed:
        return VerificationStatus.PARTIALLY_FIXED.value
    # Finding gone from the scan: the fix held for this finding.
    if introduced:
        return VerificationStatus.NEW_RISK_INTRODUCED.value
    if not package_present and before_version:
        # Package removed entirely: still a fix, but recorded explicitly.
        return VerificationStatus.VERIFIED_FIXED.value
    return VerificationStatus.VERIFIED_FIXED.value


def _note_for(status: str) -> str:
    return {
        VerificationStatus.VERIFIED_FIXED.value: "The finding is absent from the verification scan.",
        VerificationStatus.STILL_VULNERABLE.value: (
            "The finding is still detected and the package version did not change."
        ),
        VerificationStatus.PARTIALLY_FIXED.value: "The package changed but the finding is still detected.",
        VerificationStatus.NEW_RISK_INTRODUCED.value: "The fix introduced new high/critical findings.",
        VerificationStatus.VERIFICATION_FAILED.value: "The verification scan did not complete successfully.",
    }.get(status, "")


# ------------------------------------------------------------------- queries
def get_or_404(db: Session, verification_id: uuid.UUID) -> RemediationVerification:
    row = db.get(RemediationVerification, verification_id)
    if row is None:
        raise NotFoundError("Verification not found", details={"id": str(verification_id)})
    return row


def history_for_finding(db: Session, finding_id: uuid.UUID) -> list[RemediationVerification]:
    return list(
        db.execute(
            select(RemediationVerification)
            .where(RemediationVerification.finding_id == finding_id)
            .order_by(RemediationVerification.created_at.desc())
        ).scalars()
    )


def for_recommendation(db: Session, recommendation_id: uuid.UUID) -> list[RemediationVerification]:
    return list(
        db.execute(
            select(RemediationVerification)
            .where(RemediationVerification.recommendation_id == recommendation_id)
            .order_by(RemediationVerification.created_at.desc())
        ).scalars()
    )


def to_dict(row: RemediationVerification) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "recommendation_id": str(row.recommendation_id),
        "finding_id": str(row.finding_id),
        "asset_id": str(row.asset_id),
        "status": row.status,
        "before_version": row.before_version,
        "after_version": row.after_version,
        "finding_present_after": row.finding_present_after,
        "package_present_after": row.package_present_after,
        "new_findings_count": row.new_findings_count,
        "policy_result": row.policy_result,
        "evidence": row.evidence,
        "notes": row.notes,
        "ai_explanation": row.ai_explanation,
        "verification_scan_id": str(row.verification_scan_id) if row.verification_scan_id else None,
        "original_scan_id": str(row.original_scan_id) if row.original_scan_id else None,
        "verified_at": row.verified_at.isoformat() if row.verified_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# --------------------------------------------------------------- AI explainer
EXPLANATION_SYSTEM = """\
You explain the outcome of a deterministic remediation verification to a security
engineer. The status, versions and scan evidence are given to you and are final:
you may not contradict, reinterpret or override them. If something is missing,
say so. Keep it under 200 words and separate fact from interpretation.
"""


def explain(
    db: Session,
    verification_id: uuid.UUID,
    *,
    provider: AIProvider | None = None,
    principal: str = "system",
) -> RemediationVerification:
    """Attach a model-written explanation. Status is never touched."""
    settings = get_settings()
    verification = get_or_404(db, verification_id)
    provider = provider or get_provider()
    if not settings.ai_enabled or not provider.is_configured():
        raise ConflictError("AI is not configured", details={"provider": provider.name})

    from app.modules.ai.prompts.registry import PromptTemplate

    prompt = PromptTemplate(
        id="verification.explain",
        version="1",
        system=EXPLANATION_SYSTEM,
        schema_id=None,
        description="Free-text explanation of a deterministic verification result.",
    )
    request = prompt.build(
        instruction=(
            "Verification result:\n"
            f"status={verification.status}\n"
            f"before_version={verification.before_version} after_version={verification.after_version}\n"
            f"finding_present_after={verification.finding_present_after} "
            f"package_present_after={verification.package_present_after}\n"
            f"new_high_findings={verification.new_findings_count} "
            f"policy={verification.policy_result}\n"
            f"notes={verification.notes}\n"
            "Explain what this means and what the engineer should do next."
        ),
        max_output_tokens=500,
    )
    with track_execution(
        db,
        kind=AIExecutionKind.REMEDIATION.value,
        request=request,
        provider_name=provider.name,
        model=settings.ai_model,
        finding_id=verification.finding_id,
        asset_id=verification.asset_id,
        principal=principal,
    ) as execution:
        result = provider.generate(request)
        record_result(execution, result)
        verification.ai_execution_id = execution.id
    verification.ai_explanation = result.text[:4000]
    db.commit()
    return verification
