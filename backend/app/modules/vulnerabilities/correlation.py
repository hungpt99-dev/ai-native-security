"""Correlation between scanner findings, SBOM packages and vulnerability intel.

OSV is queried with the exact installed version so matches are precise for the
inventory we actually saw; KEV membership promotes severity because exploited
vulnerabilities are materially more urgent. Nothing here assumes a CVE exists.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import SEVERITY_ORDER, Severity
from app.core.logging import get_logger
from app.modules.findings.models import Finding
from app.modules.findings.service import anchor_metadata
from app.modules.scanners.base import NormalizedFinding
from app.modules.scanners.syft import SbomPackageInfo
from app.modules.vulnerabilities import repository as vuln_repo
from app.modules.vulnerabilities.models import Vulnerability
from app.modules.vulnerabilities.osv import (
    OsvClient,
    is_supported_ecosystem,
    parse_osv_vulnerability,
)

logger = get_logger(__name__)

MAX_CORRELATION_PACKAGES = 750
MAX_DETAIL_FETCHES = 150


def _promote_severity(current: str, is_kev: bool) -> str:
    if not is_kev:
        return current
    rank = SEVERITY_ORDER.get(current, 5)
    if rank > SEVERITY_ORDER[Severity.HIGH.value]:
        return Severity.HIGH.value
    return current


def correlate_packages(
    db: Session,
    *,
    asset_id: uuid.UUID,
    packages: list[SbomPackageInfo],
) -> list[NormalizedFinding]:
    """Query OSV for inventoried packages and return vulnerability findings."""
    candidate_packages = [
        pkg
        for pkg in packages
        if pkg.name and pkg.version and is_supported_ecosystem(pkg.ecosystem)
    ][:MAX_CORRELATION_PACKAGES]
    if not candidate_packages:
        return []

    client = OsvClient()
    queries = [(pkg.ecosystem or "", pkg.name, pkg.version) for pkg in candidate_packages]
    try:
        batch = client.query_batch(queries)
    except Exception:
        logger.exception("OSV batch query failed during correlation")
        return []

    kev_cves = vuln_repo.kev_cve_set(db)
    findings: list[NormalizedFinding] = []
    detail_fetches = 0
    cache: dict[str, dict[str, Any]] = {}

    for package, summaries in zip(candidate_packages, batch, strict=False):
        for summary in summaries:
            osv_id = summary.get("id")
            if not osv_id:
                continue
            payload = summary
            if not payload.get("affected"):
                if osv_id in cache:
                    payload = cache[osv_id]
                elif detail_fetches < MAX_DETAIL_FETCHES:
                    try:
                        payload = client.fetch(osv_id)
                        detail_fetches += 1
                        cache[osv_id] = payload
                    except Exception:
                        logger.warning("OSV detail fetch failed for %s", osv_id)
                        continue
                else:
                    continue

            record = parse_osv_vulnerability(payload)
            if record is None:
                continue
            db_record, _, _ = vuln_repo.upsert_vulnerability(db, record)

            is_kev = (record.cve_id in kev_cves) if record.cve_id else False
            severity = _promote_severity(record.severity, is_kev)
            fixed_versions = sorted(
                {
                    fixed
                    for affected in record.affected_packages
                    for fixed in affected.fixed_versions
                }
            )
            findings.append(
                NormalizedFinding(
                    scanner="osv",
                    rule_id=osv_id,
                    title=(record.summary or f"{osv_id} affects {package.name}")[:500],
                    description=record.description,
                    category="vulnerability",
                    severity=severity,
                    package_name=package.name,
                    package_version=package.version,
                    purl=package.purl,
                    cve_id=record.cve_id,
                    cvss_score=record.cvss_score,
                    metadata={
                        "osv_id": osv_id,
                        "cve_id": record.cve_id,
                        "is_kev": is_kev,
                        "fixed_versions": fixed_versions,
                        "ecosystem": package.ecosystem,
                        "vulnerability_id": str(db_record.id),
                        "references": [ref.url for ref in record.references][:10],
                        "published": record.published_at.isoformat() if record.published_at else None,
                        "source": "OSV",
                    },
                )
            )

    logger.info(
        "vulnerability correlation completed",
        extra={
            "extra_fields": {
                "asset_id": str(asset_id),
                "packages": len(candidate_packages),
                "matches": len(findings),
                "kev_matches": sum(1 for f in findings if f.metadata.get("is_kev")),
                "detail_fetches": detail_fetches,
            }
        },
    )
    return findings


def enrich_scan_findings(db: Session, scan_id: uuid.UUID) -> int:
    """Enrich findings of a scan with stored CVSS/KEV intelligence by CVE id."""
    rows = db.execute(
        select(Finding).where(Finding.last_scan_id == scan_id, Finding.cve_id.is_not(None))
    ).scalars().all()
    if not rows:
        return 0

    cve_ids = {row.cve_id for row in rows if row.cve_id}
    intel_rows = db.execute(
        select(Vulnerability).where(Vulnerability.cve_id.in_(cve_ids))
    ).scalars().all()
    by_cve: dict[str, list[Vulnerability]] = {}
    for entry in intel_rows:
        if entry.cve_id:
            by_cve.setdefault(entry.cve_id, []).append(entry)

    enriched = 0
    for row in rows:
        entries = by_cve.get(row.cve_id or "", [])
        if not entries:
            continue
        best = max(entries, key=lambda e: float(e.cvss_score or 0))
        is_kev = any(entry.is_kev for entry in entries)
        if best.cvss_score is not None and row.cvss_score is None:
            row.cvss_score = best.cvss_score
        if is_kev:
            row.severity = _promote_severity(row.severity, True)
        anchor_metadata(
            row,
            "intel",
            {
                "is_kev": is_kev,
                "sources": sorted({entry.source for entry in entries}),
                "cvss_score": float(best.cvss_score) if best.cvss_score is not None else None,
                "cvss_vector": best.cvss_vector,
                "kev_due_date": best.kev_due_date.isoformat() if best.kev_due_date else None,
                "kev_required_action": best.kev_required_action,
            },
        )
        enriched += 1
    db.flush()
    return enriched
