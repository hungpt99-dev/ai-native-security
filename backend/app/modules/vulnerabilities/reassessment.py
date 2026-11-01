"""Continuous vulnerability reassessment of *stored* SBOM inventory.

This is operation **C**: re-evaluate what we already know against what we have
learned since. It performs no checkout, downloads no source, runs no scanner and
generates no SBOM. The only inputs are:

* ``sbom_packages`` — the inventory preserved by the last snapshot;
* ``vulnerabilities`` / ``vulnerability_affected_packages`` / ``vulnerability_epss``
  — intelligence already ingested by the existing sync jobs;
* ``security_intelligence.versions`` — the deterministic comparator.

Everything downstream reuses the existing finding machinery: identity is
``(asset_id, fingerprint)`` exactly as for scan findings, history rows come from
``findings.service``, and enrichment is the same function the scan pipeline
calls. A vulnerability found by both paths is therefore one finding with two
evidence sources, never a duplicate.

Resolution rules (deliberately conservative):

* never resolve when the run was incomplete (component ceiling, unusable range
  data, provider/intel gaps);
* never resolve because a vulnerability record *disappeared* — a missing record
  is indistinguishable from an incomplete sync;
* resolve only on positive evidence: the exact installed version is still in the
  inventory and the stored ranges exclude it, or the snapshot proves the package
  (version) is no longer part of the composition and the finding came from an
  inventory snapshot of this asset.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    JobKind,
    SbomMonitoringKind,
    SbomMonitoringStatus,
    SbomMonitoringTrigger,
    Severity,
    VulnerabilitySource,
)
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.modules.assets.models import Asset
from app.modules.findings import service as findings_service
from app.modules.findings.models import Finding
from app.modules.sbom import lifecycle as lifecycle_module
from app.modules.sbom import service as sbom_service
from app.modules.sbom.models import Sbom, SbomPackage
from app.modules.scanners.base import NormalizedFinding
from app.modules.security_intelligence.versions import is_affected
from app.modules.vulnerabilities.correlation import enrich_findings, promote_severity
from app.modules.vulnerabilities.models import (
    Vulnerability,
    VulnerabilityAffectedPackage,
    VulnerabilityReference,
)
from app.workers import queue
from app.workers.models import Job

logger = get_logger(__name__)

INTEL_CHUNK_SIZE = 400
MAX_REFERENCES_PER_VULNERABILITY = 10

#: Scanner attribution of correlation-produced findings. Reassessment uses the
#: same value as the scan path on purpose: identity must not depend on which
#: code path noticed the vulnerability first.
SCANNER_OSV = "osv"
SCANNER_NVD = "nvd"


@dataclass
class IntelMatch:
    vulnerability_id: uuid.UUID
    source: str
    source_id: str
    osv_id: str | None
    cve_id: str | None
    summary: str | None
    description: str | None
    severity: str
    cvss_score: float | None
    is_kev: bool
    published_at: datetime | None
    ecosystem: str
    package_name: str
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    version_ranges: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def rule_id(self) -> str:
        return self.osv_id or self.cve_id or self.source_id

    @property
    def scanner(self) -> str:
        return SCANNER_OSV if self.source == VulnerabilitySource.OSV.value else SCANNER_NVD


def normalize_ecosystem(value: str | None) -> str:
    """``Debian:11`` and ``debian`` are the same ecosystem for matching."""
    return (value or "").split(":", 1)[0].strip().lower()


def evaluate_version(
    *,
    version: str | None,
    affected_versions: list[str],
    version_ranges: list[dict[str, Any]],
    ecosystem: str | None,
) -> bool | None:
    """Deterministic verdict: True affected, False not affected, None unknown.

    ``None`` is never treated as "safe" anywhere in this module.
    """
    if not version:
        return None
    if affected_versions and version in affected_versions:
        return True
    if version_ranges:
        verdict = is_affected(version, version_ranges, ecosystem)
        if verdict is not None:
            return verdict
        # Ranges existed but were unusable (e.g. GIT ranges): fall back to an
        # explicit enumeration only if the source provided one.
        if affected_versions:
            return False
        return None
    if affected_versions:
        return False
    return None


# ------------------------------------------------------------------ intel load
def load_intel(
    db: Session, packages: list[SbomPackage]
) -> tuple[dict[tuple[str, str], list[IntelMatch]], int]:
    """Load stored intelligence for the inventoried package names.

    One query per chunk for the affected-package rows, one batched query for
    references. No external API call is made: if the data is not in the
    database, it is reported as missing rather than fetched.
    """
    names = sorted({package.name.strip().lower() for package in packages if package.name})
    if not names:
        return {}, 0

    rows: list[tuple[VulnerabilityAffectedPackage, Vulnerability]] = []
    for start in range(0, len(names), INTEL_CHUNK_SIZE):
        chunk = names[start : start + INTEL_CHUNK_SIZE]
        rows.extend(
            db.execute(
                select(VulnerabilityAffectedPackage, Vulnerability)
                .join(
                    Vulnerability,
                    Vulnerability.id == VulnerabilityAffectedPackage.vulnerability_id,
                )
                .where(func.lower(VulnerabilityAffectedPackage.package_name).in_(chunk))
            ).all()
        )
    if not rows:
        return {}, 0

    vulnerability_ids = {vulnerability.id for _affected, vulnerability in rows}
    references: dict[uuid.UUID, list[str]] = defaultdict(list)
    for vulnerability_id, url in db.execute(
        select(VulnerabilityReference.vulnerability_id, VulnerabilityReference.url).where(
            VulnerabilityReference.vulnerability_id.in_(vulnerability_ids)
        )
    ).all():
        bucket = references[vulnerability_id]
        if len(bucket) < MAX_REFERENCES_PER_VULNERABILITY and url:
            bucket.append(str(url))

    # One advisory can be split across several affected-package rows, one per
    # version track (e.g. ``>=4 <5`` and ``>=0 <1.1.13`` for the same npm
    # package). They are the same advisory, so their ranges must be merged:
    # evaluating only the first row would silently declare an affected version
    # safe (and could create the mirror-image false negative).
    merged: dict[tuple[uuid.UUID, str, str], IntelMatch] = {}
    for affected, vulnerability in rows:
        ecosystem_key = normalize_ecosystem(affected.ecosystem)
        name_key = (affected.package_name or "").lower()
        key = (vulnerability.id, ecosystem_key, name_key)
        match = merged.get(key)
        if match is None:
            match = IntelMatch(
                vulnerability_id=vulnerability.id,
                source=vulnerability.source,
                source_id=vulnerability.source_id,
                osv_id=vulnerability.osv_id,
                cve_id=vulnerability.cve_id,
                summary=vulnerability.summary,
                description=vulnerability.description,
                severity=vulnerability.severity or Severity.UNKNOWN.value,
                cvss_score=(
                    float(vulnerability.cvss_score)
                    if vulnerability.cvss_score is not None
                    else None
                ),
                is_kev=vulnerability.is_kev,
                published_at=vulnerability.published_at,
                ecosystem=affected.ecosystem or "",
                package_name=affected.package_name or "",
                references=references.get(vulnerability.id, []),
            )
            merged[key] = match
        match.affected_versions = sorted(
            set(match.affected_versions)
            | {str(value) for value in affected.affected_versions or []}
        )
        match.fixed_versions = sorted(
            set(match.fixed_versions)
            | {str(value) for value in affected.fixed_versions or []}
        )
        for entry in affected.version_ranges or []:
            # Commit ranges (``type: GIT``) cannot be evaluated against a
            # version string. Keeping them would produce a match nobody can
            # explain, so they are dropped and the component is reported as
            # "unknown" instead of "affected" or "safe".
            if str((entry or {}).get("type") or "").upper() == "GIT":
                continue
            match.version_ranges.append(dict(entry))

    index: dict[tuple[str, str], list[IntelMatch]] = defaultdict(list)
    for match in merged.values():
        index[(normalize_ecosystem(match.ecosystem), match.package_name.lower())].append(match)
    return index, len(vulnerability_ids)


def _matching_intel(
    index: dict[tuple[str, str], list[IntelMatch]], package: SbomPackage
) -> list[IntelMatch]:
    """Intel rows for one package, ecosystem-qualified when both sides say it."""
    candidates: list[IntelMatch] = []
    seen: set[uuid.UUID] = set()
    ecosystem = normalize_ecosystem(package.ecosystem)
    for key in ((ecosystem, package.name.lower()), ("", package.name.lower())):
        for match in index.get(key, []):
            # An unspecified ecosystem on either side cannot be used to exclude
            # a candidate; a mismatch on both sides can.
            if (
                ecosystem
                and match.ecosystem
                and normalize_ecosystem(match.ecosystem) != ecosystem
            ):
                continue
            if match.vulnerability_id in seen:
                continue
            seen.add(match.vulnerability_id)
            candidates.append(match)
    return candidates


def _deduplicate(matches: list[IntelMatch]) -> list[IntelMatch]:
    """One finding per (rule identity, package): OSV wins over NVD.

    OSV carries package ranges; NVD often only carries the CVE. Keeping both
    would create two findings for one problem, which is exactly the duplication
    this design forbids.
    """
    chosen: dict[str, IntelMatch] = {}
    for match in matches:
        key = (match.osv_id or match.cve_id or match.source_id or "").lower()
        existing = chosen.get(key)
        if existing is None or (
            existing.source != VulnerabilitySource.OSV.value
            and match.source == VulnerabilitySource.OSV.value
        ):
            chosen[key] = match
    return sorted(chosen.values(), key=lambda item: item.rule_id)


# ------------------------------------------------------------------- findings
def _build_finding(
    match: IntelMatch, package: SbomPackage, snapshot: Sbom
) -> NormalizedFinding:
    severity = promote_severity(match.severity, match.is_kev)
    return NormalizedFinding(
        scanner=match.scanner,
        rule_id=match.rule_id,
        title=(match.summary or f"{match.rule_id} affects {package.name}")[:500],
        description=match.description,
        category="vulnerability",
        severity=severity,
        package_name=package.name,
        package_version=package.version,
        purl=package.purl,
        cve_id=match.cve_id,
        cvss_score=match.cvss_score,
        metadata={
            "osv_id": match.osv_id,
            "cve_id": match.cve_id,
            "is_kev": match.is_kev,
            "fixed_versions": sorted(set(match.fixed_versions)),
            "ecosystem": package.ecosystem or match.ecosystem,
            "vulnerability_id": str(match.vulnerability_id),
            "references": match.references,
            "published": match.published_at.isoformat() if match.published_at else None,
            "source": match.source,
            "detection": "SBOM_REASSESSMENT",
            # Provenance for resolution: this finding is tied to an inventory
            # snapshot of this asset, not to a working tree.
            "inventory_snapshot_id": str(snapshot.id),
            "sbom_id": str(snapshot.id),
            "sbom_commit_sha": snapshot.commit_sha,
            "dependency_fingerprint": snapshot.dependency_fingerprint,
        },
    )


# ------------------------------------------------------------------ resolution
@dataclass
class ResolutionOutcome:
    resolved: int = 0
    needs_review: int = 0
    unresolved_unknown: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def add(self, reason: str) -> None:
        self.reasons[reason] = self.reasons.get(reason, 0) + 1


def _resolve_from_inventory(
    db: Session,
    *,
    asset_id: uuid.UUID,
    snapshot: Sbom,
    packages: list[SbomPackage],
    intel_index: dict[tuple[str, str], list[IntelMatch]],
    allow_resolution: bool,
) -> ResolutionOutcome:
    """Resolve findings only on positive, deterministic evidence."""
    outcome = ResolutionOutcome()
    if not allow_resolution:
        return outcome

    inventory = {(pkg.name.strip().lower(), pkg.version) for pkg in packages}
    names = {pkg.name.strip().lower() for pkg in packages}
    by_key = {(pkg.name.strip().lower(), pkg.version): pkg for pkg in packages}

    rows = db.execute(
        select(Finding).where(
            Finding.asset_id == asset_id,
            Finding.status.in_(ACTIVE_FINDING_STATUSES),
            Finding.scanner.in_([SCANNER_OSV, SCANNER_NVD]),
            Finding.package_name.is_not(None),
            Finding.package_version.is_not(None),
        )
    ).scalars().all()

    for finding in rows:
        name = (finding.package_name or "").strip().lower()
        version = finding.package_version or ""
        metadata = finding.metadata_json or {}
        provenance = metadata.get("inventory_snapshot_id")
        exact_key = (name, version)

        if exact_key in inventory:
            package = by_key[exact_key]
            candidates = [
                match
                for match in _matching_intel(intel_index, package)
                if (match.osv_id or match.cve_id or match.source_id or "").lower()
                == (finding.rule_id or "").lower()
            ]
            if not candidates:
                # The exact version is still installed but the vulnerability
                # record is gone. A missing record is not evidence of a fix.
                outcome.needs_review += 1
                outcome.add("intelligence_missing_for_finding")
                continue
            verdicts = [
                evaluate_version(
                    version=package.version,
                    affected_versions=match.affected_versions,
                    version_ranges=match.version_ranges,
                    ecosystem=package.ecosystem or match.ecosystem,
                )
                for match in candidates
            ]
            if any(verdict is True for verdict in verdicts):
                continue
            if any(verdict is None for verdict in verdicts):
                outcome.unresolved_unknown += 1
                outcome.add("range_data_unusable")
                continue
            if findings_service.resolve_finding(
                db,
                finding,
                actor="sbom_monitoring",
                note=(
                    "Stored intelligence no longer marks the installed version as "
                    f"affected ({package.name} {package.version}, snapshot {snapshot.id})"
                ),
            ):
                outcome.resolved += 1
                outcome.add("version_no_longer_affected")
            continue

        # The exact version is no longer part of the composition.
        if not provenance:
            # No inventory provenance: this finding may belong to another branch
            # or an older scan. Reassessment does not get to close it.
            outcome.needs_review += 1
            outcome.add("no_inventory_provenance")
            continue
        reason = (
            "package_version_changed" if name in names else "package_removed_from_inventory"
        )
        if findings_service.resolve_finding(
            db,
            finding,
            actor="sbom_monitoring",
            note=(
                f"{name} {version} is not part of snapshot {snapshot.id} "
                f"({reason.replace('_', ' ')})"
            ),
        ):
            outcome.resolved += 1
            outcome.add(reason)
    db.flush()
    return outcome


# --------------------------------------------------------------- orchestration
def reassess_asset(
    db: Session,
    *,
    asset_id: uuid.UUID,
    trigger: str = SbomMonitoringTrigger.MANUAL.value,
    sbom_id: uuid.UUID | None = None,
    job_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Re-evaluate one asset's stored inventory. No repository access at all."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found", details={"asset_id": str(asset_id)})

    with lifecycle_module.asset_operation_lock(db, asset.id, "reassess") as acquired:
        if not acquired:
            return {
                "asset_id": str(asset.id),
                "status": "SKIPPED",
                "reason": "another reassessment is running",
            }

        snapshot = (
            db.get(Sbom, sbom_id)
            if sbom_id is not None
            else sbom_service.latest_sbom_for_asset(db, asset.id)
        )
        if snapshot is not None and snapshot.asset_id != asset.id:
            raise NotFoundError(
                "SBOM snapshot not found for this asset",
                details={"asset_id": str(asset.id), "sbom_id": str(sbom_id)},
            )

        run = lifecycle_module.start_run(
            db,
            asset_id=asset.id,
            kind=SbomMonitoringKind.VULNERABILITY_REASSESSMENT.value,
            trigger=trigger,
            job_id=job_id,
            sbom_id=snapshot.id if snapshot else None,
            head_commit_sha=snapshot.commit_sha if snapshot else None,
            dependency_fingerprint_value=(
                snapshot.dependency_fingerprint if snapshot else None
            ),
        )
        run_id = run.id

        if snapshot is None:
            lifecycle_module.finish_run(
                db,
                run,
                status=SbomMonitoringStatus.SKIPPED.value,
                skipped_reason="no SBOM snapshot to evaluate",
                metrics={"reason": "no_snapshot"},
            )
            return {"asset_id": str(asset.id), "status": "SKIPPED", "reason": "no snapshot"}

        try:
            settings = get_settings()
            packages = sbom_service.packages_for_sbom(
                db, snapshot.id, limit=settings.sbom_max_reassessment_components + 1
            )
            truncated = len(packages) > settings.sbom_max_reassessment_components
            if truncated:
                packages = packages[: settings.sbom_max_reassessment_components]

            intel_index, vulnerability_rows = load_intel(db, packages)

            normalized: list[NormalizedFinding] = []
            evaluated = 0
            with_intel = 0
            unknown = 0
            distinct_vulnerabilities: set[uuid.UUID] = set()

            for package in packages:
                if not package.name or not package.version:
                    unknown += 1
                    continue
                candidates = _deduplicate(_matching_intel(intel_index, package))
                if not candidates:
                    evaluated += 1
                    continue
                with_intel += 1
                package_unknown = False
                for match in candidates:
                    verdict = evaluate_version(
                        version=package.version,
                        affected_versions=match.affected_versions,
                        version_ranges=match.version_ranges,
                        ecosystem=package.ecosystem or match.ecosystem,
                    )
                    if verdict is None:
                        package_unknown = True
                        continue
                    if verdict:
                        normalized.append(_build_finding(match, package, snapshot))
                        distinct_vulnerabilities.add(match.vulnerability_id)
                if package_unknown:
                    unknown += 1
                evaluated += 1

            counts = findings_service.record_findings(
                db,
                asset_id=asset.id,
                scan_id=None,
                normalized=normalized,
                discovery_source="SBOM_REASSESSMENT",
                actor="sbom_monitoring",
            )

            new_finding_ids = db.execute(
                select(Finding.id).where(
                    Finding.asset_id == asset.id,
                    Finding.discovery_source == "SBOM_REASSESSMENT",
                    Finding.first_detected_at >= run.started_at,
                    Finding.status.in_(ACTIVE_FINDING_STATUSES),
                )
            ).scalars().all()
            touch_rows = db.execute(
                select(Finding).where(
                    Finding.asset_id == asset.id,
                    Finding.scanner.in_([SCANNER_OSV, SCANNER_NVD]),
                    Finding.status.in_(ACTIVE_FINDING_STATUSES),
                )
            ).scalars().all()
            enrichment = enrich_findings(db, list(touch_rows))
            db.commit()

            # Absence is only meaningful for a complete inventory. Other
            # partial results (unusable ranges on unrelated packages) downgrade
            # the run status but do not invalidate exact-version evidence.
            resolution = _resolve_from_inventory(
                db,
                asset_id=asset.id,
                snapshot=snapshot,
                packages=packages,
                intel_index=intel_index,
                allow_resolution=not truncated,
            )
            db.commit()

            status = SbomMonitoringStatus.SUCCEEDED.value
            if truncated or unknown > 0:
                status = SbomMonitoringStatus.PARTIAL.value
            metrics = {
                "packages": len(packages),
                "components_with_intel": with_intel,
                "vulnerability_records_considered": vulnerability_rows,
                "distinct_vulnerabilities_matched": len(distinct_vulnerabilities),
                "unknown_evaluations": unknown,
                "component_limit": settings.sbom_max_reassessment_components,
                "component_limit_reached": truncated,
                "enriched": enrichment["enriched"],
                "epss_updated": enrichment["epss_updated"],
                "resolution_reasons": resolution.reasons,
                "needs_review": resolution.needs_review,
                "reopened": counts["reopened"],
                "new_finding_ids": [str(value) for value in new_finding_ids],
                "repository_accessed": False,
                "scanners_executed": [],
            }
            lifecycle_module.finish_run(
                db,
                run,
                status=status,
                components_evaluated=evaluated,
                findings_created=counts["created"],
                findings_updated=counts["updated"],
                findings_resolved=resolution.resolved,
                new_kev_findings=enrichment["kev_new"],
                failure_count=unknown,
                metrics=metrics,
                error=(
                    f"{unknown} component(s) could not be evaluated deterministically"
                    if unknown
                    else None
                ),
                sbom_id=snapshot.id,
            )
            logger.info(
                "sbom vulnerability reassessment finished",
                extra={
                    "extra_fields": {
                        "asset_id": str(asset.id),
                        "sbom_id": str(snapshot.id),
                        "components": evaluated,
                        "created": counts["created"],
                        "updated": counts["updated"],
                        "resolved": resolution.resolved,
                        "new_kev": enrichment["kev_new"],
                        "status": status,
                    }
                },
            )
            return {
                "asset_id": str(asset.id),
                "sbom_id": str(snapshot.id),
                "run_id": str(run_id),
                "status": status,
                "components_evaluated": evaluated,
                "findings_created": counts["created"],
                "findings_updated": counts["updated"],
                "findings_resolved": resolution.resolved,
                "new_kev_findings": enrichment["kev_new"],
                "unknown_evaluations": unknown,
                "new_finding_ids": [str(value) for value in new_finding_ids],
            }
        except Exception as exc:
            logger.exception(
                "sbom vulnerability reassessment failed",
                extra={"extra_fields": {"asset_id": str(asset.id)}},
            )
            lifecycle_module.fail_run(db, run_id, f"{exc.__class__.__name__}: {exc}")
            raise


def reassess_all(db: Session, *, trigger: str, job_id: uuid.UUID | None = None) -> dict[str, Any]:
    """Scheduled entry point: reassess every asset that has a stored snapshot.

    Assets without a snapshot are skipped (nothing to evaluate) and the skip is
    visible in the summary rather than reported as a healthy evaluation.
    """
    assets = db.execute(
        select(Asset.id)
        .join(Sbom, Sbom.asset_id == Asset.id)
        .group_by(Asset.id)
        .order_by(Asset.id)
    ).scalars().all()

    results: list[dict[str, Any]] = []
    for asset_id in assets:
        results.append(reassess_asset(db, asset_id=asset_id, trigger=trigger, job_id=job_id))
    return {
        "assets": len(assets),
        "results": results,
        "failures": sum(1 for entry in results if entry.get("status") == "FAILED"),
        "partial": sum(1 for entry in results if entry.get("status") == "PARTIAL"),
    }


def enqueue_after_intel_sync(db: Session, *, source: str, changed: int) -> Job | None:
    """Queue one global reassessment when a sync actually changed intelligence."""
    settings = get_settings()
    if not settings.sbom_monitoring_enabled or not settings.sbom_reassess_after_intel_sync:
        return None
    if changed <= 0:
        return None
    job, _created = queue.enqueue_once(
        db,
        JobKind.SBOM_VULNERABILITY_REASSESSMENT,
        {"trigger": SbomMonitoringTrigger.INTEL_SYNC.value, "source": source},
        priority=240,
    )
    logger.info(
        "reassessment queued after intelligence sync",
        extra={
            "extra_fields": {
                "source": source,
                "changed_records": changed,
                "job_id": str(job.id) if job else None,
            }
        },
    )
    return job
