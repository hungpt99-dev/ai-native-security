"""Remediation recommendations and the approval lifecycle.

Two invariants are enforced here, not by the prompt:

* a recommended version must exist in authoritative vulnerability data and must
  actually leave the affected range (deterministic check, via
  ``security_intelligence.versions``);
* nothing is applied. Proposals move through an explicit state machine and stop
  at ``APPROVED`` until a human acts.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    ALLOWED_REMEDIATION_TRANSITIONS,
    AIExecutionKind,
    DecisionType,
    RemediationStatus,
    RemediationStrategy,
)
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.modules.ai import agents
from app.modules.ai.errors import (
    AIBudgetExceededError,
    AIProviderError,
    AIRateLimitedError,
    AIResponseError,
    AIUnavailableError,
)
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.providers.registry import get_provider
from app.modules.ai.services import budgets
from app.modules.ai.services.executions import record_result, track_execution
from app.modules.findings.models import Finding
from app.modules.knowledge_base.service import record_decision
from app.modules.remediation.models import RemediationRecommendation
from app.modules.risk_analysis import service as risk_service
from app.modules.security_intelligence.context_builder import SecurityContextBuilder
from app.modules.security_intelligence.schemas import SecurityContext
from app.modules.security_intelligence.versions import (
    explain_comparison,
    is_fixed_version_valid,
)
from app.modules.security_policies import service as policies_service

logger = get_logger(__name__)

_AI_FAILURES = (
    AIUnavailableError,
    AIProviderError,
    AIRateLimitedError,
    AIResponseError,
    AIBudgetExceededError,
)


def propose(
    db: Session,
    finding_id: uuid.UUID,
    *,
    provider: AIProvider | None = None,
    principal: str = "system",
) -> RemediationRecommendation:
    settings = get_settings()
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError("Finding not found", details={"finding_id": str(finding_id)})

    policy_row = policies_service.active_policy(db, "REMEDIATION")
    policy = {
        **policies_service.DEFAULT_REMEDIATION_POLICY,
        **((policy_row.config if policy_row else {}) or {}),
    }

    builder = SecurityContextBuilder(settings)
    context = builder.build(db, finding_id)
    snapshot = builder.persist(db, context, finding=finding)
    db.commit()

    risk = risk_service.latest(db, finding.id)
    provider = provider or get_provider()
    settings = get_settings()

    output = None
    execution_id = None
    failure: dict[str, Any] | None = None
    if settings.ai_enabled and provider.is_configured():
        try:
            budgets.enforce(db)
            from app.modules.ai.services.investigations import latest as latest_investigation

            investigation = latest_investigation(db, finding.id)
            request = agents.remediation.build_request(
                context,
                risk=risk,
                investigation_summary=investigation.summary if investigation else None,
            )
            with track_execution(
                db,
                kind=AIExecutionKind.REMEDIATION.value,
                request=request,
                provider_name=provider.name,
                model=settings.ai_model,
                finding_id=finding.id,
                asset_id=finding.asset_id,
                context_snapshot_id=snapshot.id,
                principal=principal,
            ) as execution:
                analysis = agents.remediation.run(
                    provider,
                    context,
                    risk=risk,
                    investigation_summary=investigation.summary if investigation else None,
                    request=request,
                )
                record_result(execution, analysis.result)
                execution_id = execution.id
            output = analysis.output
        except _AI_FAILURES as exc:
            failure = {"code": getattr(exc, "code", "ai_error"), "message": str(exc)[:500]}

    recommendation = _build_recommendation(
        db,
        finding=finding,
        context=context,
        snapshot_id=snapshot.id,
        output=output,
        execution_id=execution_id,
        failure=failure,
        policy=policy,
        risk_id=risk.id if risk else None,
        settings=settings,
    )
    db.add(recommendation)
    db.flush()
    transition(
        db,
        recommendation,
        RemediationStatus.AWAITING_APPROVAL.value,
        actor="system",
        note="Proposal generated; waiting for human approval.",
    )
    db.commit()
    logger.info(
        "remediation proposal stored",
        extra={
            "extra_fields": {
                "recommendation_id": str(recommendation.id),
                "finding_id": str(finding.id),
                "strategy": recommendation.strategy,
                "status": recommendation.status,
                "recommended_version": recommendation.recommended_version,
                "version_verified": recommendation.version_verified,
            }
        },
    )
    return recommendation


def _build_recommendation(
    db: Session,
    *,
    finding: Finding,
    context: SecurityContext,
    snapshot_id: uuid.UUID,
    output: Any,
    execution_id: uuid.UUID | None,
    failure: dict[str, Any] | None,
    policy: dict[str, Any],
    risk_id: uuid.UUID | None,
    settings: Any,
) -> RemediationRecommendation:
    missing = [item.model_dump(mode="json") for item in context.missing_information]
    fixed_versions = context.vulnerability.get("fixed_versions") or []
    ecosystem = context.vulnerability.get("ecosystem") or (finding.metadata_json or {}).get("ecosystem")

    strategy = RemediationStrategy.MITIGATION.value
    summary = None
    reasoning = None
    recommended_version = None
    version_verified = False
    patch = None
    patch_format = None
    changes: list[dict[str, Any]] = []
    breaking: list[str] = []
    tests: list[str] = []
    improvement = None
    target_package = finding.package_name

    if output is not None:
        strategy = output.strategy
        if strategy not in (policy.get("allowed_strategies") or [strategy]):
            missing.append(
                {
                    "code": "strategy_not_allowed_by_policy",
                    "message": f"Strategy {strategy} is not allowed by policy; downgraded to MITIGATION.",
                    "affects": ["remediation"],
                }
            )
            strategy = RemediationStrategy.MITIGATION.value
        summary = output.summary
        reasoning = output.reasoning
        target_package = output.target_package or target_package
        breaking = output.breaking_change_risks
        tests = output.recommended_tests
        improvement = output.expected_security_improvement
        changes = [change.model_dump(mode="json") for change in output.changes]

        if output.patch and policy.get("allow_patch_proposals", True):
            limit = int(policy.get("max_patch_chars", 12000))
            patch = output.patch[:limit]
            patch_format = "unified-diff"
            if len(output.patch) > limit:
                missing.append(
                    {
                        "code": "patch_truncated",
                        "message": "The proposed patch exceeded the configured size limit and was truncated.",
                        "affects": ["patch"],
                    }
                )
        elif output.patch:
            missing.append(
                {
                    "code": "patch_disallowed_by_policy",
                    "message": "The policy forbids patch proposals; the patch was discarded.",
                    "affects": ["patch"],
                }
            )

        # ---- deterministic version validation ---------------------------
        if output.recommended_version:
            candidate = output.recommended_version.strip()
            authoritative = candidate in {str(version) for version in fixed_versions}
            valid = is_fixed_version_valid(
                candidate,
                fixed_versions=fixed_versions,
                current_version=finding.package_version,
                ecosystem=ecosystem,
            )
            if not fixed_versions:
                missing.append(
                    {
                        "code": "recommended_version_rejected",
                        "message": (
                            f"The model proposed {candidate} but no authoritative fixed version is "
                            "known, so the recommendation cannot be validated."
                        ),
                        "affects": ["remediation"],
                    }
                )
            elif not authoritative or valid is not True:
                missing.append(
                    {
                        "code": "recommended_version_rejected",
                        "message": (
                            f"The model proposed {candidate}, which authoritative fixed-version data "
                            f"does not support (known fixed versions: {fixed_versions}, "
                            "comparison: "
                            f"{explain_comparison(candidate, str(fixed_versions[0]), ecosystem)})."
                        ),
                        "affects": ["remediation"],
                    }
                )
            else:
                recommended_version = candidate
                version_verified = True
    if failure:
        missing.append(
            {
                "code": "ai_unavailable_for_remediation",
                "message": (
                    f"AI recommendation failed ({failure['code']}); the deterministic fixed version "
                    "is shown without a model explanation."
                ),
                "affects": ["remediation"],
            }
        )
        if fixed_versions:
            recommended_version = min(fixed_versions)
            version_verified = True
            strategy = RemediationStrategy.DEPENDENCY_UPGRADE.value
            summary = f"Upgrade {target_package or 'the package'} to {recommended_version}."
            reasoning = "Derived deterministically from authoritative fixed-version data (no AI involved)."
        else:
            strategy = RemediationStrategy.NO_ACTION_AVAILABLE.value
            summary = "No fixed version is known; manual mitigation is required."
            reasoning = "No authoritative fixed version exists in the platform's vulnerability data."

    return RemediationRecommendation(
        finding_id=finding.id,
        asset_id=finding.asset_id,
        risk_assessment_id=risk_id,
        context_snapshot_id=snapshot_id,
        ai_execution_id=execution_id,
        strategy=strategy,
        status=RemediationStatus.REMEDIATION_PROPOSED.value,
        summary=summary,
        reasoning=reasoning,
        target_package=target_package,
        current_version=finding.package_version,
        recommended_version=recommended_version,
        version_verified=version_verified,
        patch=patch,
        patch_format=patch_format,
        changes=changes,
        breaking_change_risks=breaking,
        recommended_tests=tests,
        expected_security_improvement=improvement,
        missing_information=missing,
        evidence=[
            {
                "key": item.key,
                "kind": item.kind,
                "sha256": item.sha256,
                "locator": item.locator,
            }
            for item in context.evidence
        ],
        requires_human_approval=bool(policy.get("require_human_approval", True)),
        model=settings.ai_model if output else None,
        prompt_version=agents.remediation.REMEDIATION_PROMPT.version if output else None,
    )


# ------------------------------------------------------------------ lifecycle
def get_or_404(db: Session, recommendation_id: uuid.UUID) -> RemediationRecommendation:
    row = db.get(RemediationRecommendation, recommendation_id)
    if row is None:
        raise NotFoundError("Remediation recommendation not found", details={"id": str(recommendation_id)})
    return row


def transition(
    db: Session,
    recommendation: RemediationRecommendation,
    target: str,
    *,
    actor: str = "api",
    note: str | None = None,
) -> RemediationRecommendation:
    target = target.upper()
    current = recommendation.status
    if target == current:
        return recommendation
    allowed = ALLOWED_REMEDIATION_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise ConflictError(
            "Invalid remediation transition",
            details={"from": current, "to": target, "allowed": sorted(allowed)},
        )
    recommendation.status = target
    if target == RemediationStatus.APPROVED.value:
        from datetime import UTC, datetime

        recommendation.approved_by = actor
        recommendation.approved_at = datetime.now(UTC)
    if target == RemediationStatus.REJECTED.value:
        recommendation.rejected_reason = note
    db.flush()
    logger.info(
        "remediation transition",
        extra={
            "extra_fields": {
                "recommendation_id": str(recommendation.id),
                "from": current,
                "to": target,
                "actor": actor,
            }
        },
    )
    return recommendation


def approve(
    db: Session, recommendation_id: uuid.UUID, *, actor: str, note: str | None = None
) -> RemediationRecommendation:
    recommendation = get_or_404(db, recommendation_id)
    recommendation = transition(db, recommendation, RemediationStatus.APPROVED.value, actor=actor, note=note)
    record_decision(
        db,
        finding_id=recommendation.finding_id,
        asset_id=recommendation.asset_id,
        decision_type=DecisionType.APPROVE_REMEDIATION.value,
        actor=actor,
        reason=note,
        recommendation_id=recommendation.id,
        remediation_status=recommendation.status,
        metadata={"recommended_version": recommendation.recommended_version},
    )
    db.commit()
    return recommendation


def reject(db: Session, recommendation_id: uuid.UUID, *, actor: str, note: str) -> RemediationRecommendation:
    recommendation = get_or_404(db, recommendation_id)
    recommendation = transition(db, recommendation, RemediationStatus.REJECTED.value, actor=actor, note=note)
    record_decision(
        db,
        finding_id=recommendation.finding_id,
        asset_id=recommendation.asset_id,
        decision_type=DecisionType.REJECT_REMEDIATION.value,
        actor=actor,
        reason=note,
        recommendation_id=recommendation.id,
        remediation_status=recommendation.status,
        metadata={},
    )
    db.commit()
    return recommendation


def list_recommendations(
    db: Session,
    params: PageParams,
    *,
    status: str | None = None,
    asset_id: uuid.UUID | None = None,
) -> tuple[list[RemediationRecommendation], int]:
    stmt = select(RemediationRecommendation)
    if status:
        stmt = stmt.where(RemediationRecommendation.status == status.upper())
    if asset_id:
        stmt = stmt.where(RemediationRecommendation.asset_id == asset_id)
    stmt = stmt.order_by(RemediationRecommendation.created_at.desc())
    return paginate(db, stmt, params)


def for_finding(db: Session, finding_id: uuid.UUID) -> list[RemediationRecommendation]:
    return list(
        db.execute(
            select(RemediationRecommendation)
            .where(RemediationRecommendation.finding_id == finding_id)
            .order_by(RemediationRecommendation.created_at.desc())
        ).scalars()
    )


def to_dict(row: RemediationRecommendation) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "finding_id": str(row.finding_id),
        "asset_id": str(row.asset_id),
        "strategy": row.strategy,
        "status": row.status,
        "summary": row.summary,
        "reasoning": row.reasoning,
        "target_package": row.target_package,
        "current_version": row.current_version,
        "recommended_version": row.recommended_version,
        "version_verified": row.version_verified,
        "patch": row.patch,
        "patch_format": row.patch_format,
        "changes": row.changes,
        "breaking_change_risks": row.breaking_change_risks,
        "recommended_tests": row.recommended_tests,
        "expected_security_improvement": row.expected_security_improvement,
        "missing_information": row.missing_information,
        "requires_human_approval": row.requires_human_approval,
        "approved_by": row.approved_by,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "rejected_reason": row.rejected_reason,
        "model": row.model,
        "prompt_version": row.prompt_version,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
