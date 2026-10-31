"""Persistence layer for normalized vulnerability intelligence.

Upserts are keyed by ``(source, source_id)`` and always replace the
denormalized children (references, affected packages) so re-syncs converge
instead of duplicating rows.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.enums import VulnerabilitySource
from app.modules.vulnerabilities.models import (
    Vulnerability,
    VulnerabilityAffectedPackage,
    VulnerabilityReference,
    VulnerabilitySyncHistory,
)
from app.modules.vulnerabilities.records import VulnerabilityRecord


def _clip(value: str | None, limit: int) -> str | None:
    """Trim free-form upstream text to the column width."""
    if value is None:
        return None
    return value[:limit]


def _payload_hash(record: VulnerabilityRecord) -> str:
    payload = {
        "summary": record.summary,
        "description": record.description,
        "cvss_score": record.cvss_score,
        "severity": record.severity,
        "modified_at": record.modified_at.isoformat() if record.modified_at else None,
        "is_kev": record.is_kev,
        "references": [ref.url for ref in record.references],
        "affected": [
            (pkg.ecosystem, pkg.package_name, sorted(pkg.affected_versions))
            for pkg in record.affected_packages
        ],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def upsert_vulnerability(db: Session, record: VulnerabilityRecord) -> tuple[Vulnerability, bool, bool]:
    """Insert or update one record. Returns (row, created, changed)."""
    existing = db.execute(
        select(Vulnerability).where(
            Vulnerability.source == record.source,
            Vulnerability.source_id == record.source_id,
        )
    ).scalar_one_or_none()

    digest = _payload_hash(record)
    if existing is None:
        vulnerability = Vulnerability(
            source=record.source,
            source_id=record.source_id,
            cve_id=record.cve_id,
            osv_id=record.osv_id,
            summary=_clip(record.summary, 1000),
            description=record.description,
            cvss_score=record.cvss_score,
            cvss_vector=record.cvss_vector,
            severity=record.severity,
            published_at=record.published_at,
            modified_at=record.modified_at,
            is_kev=record.is_kev,
            kev_due_date=record.kev_due_date,
            kev_required_action=record.kev_required_action,
            source_payload_hash=digest,
        )
        db.add(vulnerability)
        db.flush()
        _replace_children(db, vulnerability, record)
        return vulnerability, True, True

    if existing.source_payload_hash == digest:
        # Still ensure the KEV flag stays accurate for OSV/NVD rows.
        if record.is_kev and not existing.is_kev:
            existing.is_kev = True
            return existing, False, True
        return existing, False, False

    existing.cve_id = record.cve_id or existing.cve_id
    existing.osv_id = record.osv_id or existing.osv_id
    existing.summary = _clip(record.summary, 1000) or existing.summary
    existing.description = record.description or existing.description
    existing.cvss_score = record.cvss_score if record.cvss_score is not None else existing.cvss_score
    existing.cvss_vector = record.cvss_vector or existing.cvss_vector
    existing.severity = record.severity if record.severity != "UNKNOWN" else existing.severity
    existing.published_at = record.published_at or existing.published_at
    existing.modified_at = record.modified_at or existing.modified_at
    existing.is_kev = existing.is_kev or record.is_kev
    existing.kev_due_date = record.kev_due_date or existing.kev_due_date
    existing.kev_required_action = record.kev_required_action or existing.kev_required_action
    existing.source_payload_hash = digest
    _replace_children(db, existing, record)
    db.flush()
    return existing, False, True


def _replace_children(db: Session, vulnerability: Vulnerability, record: VulnerabilityRecord) -> None:
    db.execute(
        delete(VulnerabilityReference).where(
            VulnerabilityReference.vulnerability_id == vulnerability.id
        )
    )
    db.execute(
        delete(VulnerabilityAffectedPackage).where(
            VulnerabilityAffectedPackage.vulnerability_id == vulnerability.id
        )
    )
    seen_urls: set[str] = set()
    for ref in record.references:
        if not ref.url or ref.url in seen_urls:
            continue
        seen_urls.add(ref.url)
        db.add(
            VulnerabilityReference(
                vulnerability_id=vulnerability.id,
                url=ref.url,
                ref_type=_clip(ref.ref_type, 64),
                source=_clip(ref.source, 32),
            )
        )
    for package in record.affected_packages:
        db.add(
            VulnerabilityAffectedPackage(
                vulnerability_id=vulnerability.id,
                ecosystem=_clip(package.ecosystem, 64) or "",
                package_name=_clip(package.package_name, 255) or "",
                purl=_clip(package.purl, 500),
                affected_versions=list(package.affected_versions),
                fixed_versions=list(package.fixed_versions),
                version_ranges=list(package.version_ranges),
            )
        )


def bulk_upsert(db: Session, records: Iterable[VulnerabilityRecord]) -> tuple[int, int, int]:
    created = updated = unchanged = 0
    for record in records:
        _, was_created, changed = upsert_vulnerability(db, record)
        if was_created:
            created += 1
        elif changed:
            updated += 1
        else:
            unchanged += 1
    db.flush()
    return created, updated, unchanged


def apply_kev_flags(
    db: Session, cve_ids: Iterable[str], *, due_dates: dict[str, Any] | None = None
) -> int:
    """Mark already-stored OSV/NVD records as KEV when a CVE is exploited."""
    ids = [c for c in {str(cve).upper() for cve in cve_ids} if c]
    if not ids:
        return 0
    rows = db.execute(
        select(Vulnerability).where(
            Vulnerability.cve_id.in_(ids),
            Vulnerability.source != VulnerabilitySource.CISA_KEV.value,
            Vulnerability.is_kev.is_(False),
        )
    ).scalars().all()
    for row in rows:
        row.is_kev = True
        if due_dates and row.cve_id in due_dates:
            row.kev_due_date = due_dates[row.cve_id]  # type: ignore[assignment]
    db.flush()
    return len(rows)


def get_by_cve(db: Session, cve_id: str) -> list[Vulnerability]:
    return list(
        db.execute(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper())
        ).scalars()
    )


def kev_cve_set(db: Session) -> set[str]:
    rows = db.execute(
        select(Vulnerability.cve_id).where(
            Vulnerability.source == VulnerabilitySource.CISA_KEV.value,
            Vulnerability.cve_id.is_not(None),
        )
    ).scalars()
    return {str(row) for row in rows if row}


def last_successful_sync(db: Session, source: str) -> VulnerabilitySyncHistory | None:
    return db.execute(
        select(VulnerabilitySyncHistory)
        .where(
            VulnerabilitySyncHistory.source == source,
            VulnerabilitySyncHistory.status.in_(["SUCCESS", "PARTIAL"]),
        )
        .order_by(VulnerabilitySyncHistory.finished_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def start_sync(db: Session, source: str) -> VulnerabilitySyncHistory:
    from datetime import UTC, datetime

    entry = VulnerabilitySyncHistory(
        source=source, status="RUNNING", started_at=datetime.now(UTC)
    )
    db.add(entry)
    db.flush()
    return entry


def count_vulnerabilities(db: Session) -> int:
    return int(db.execute(select(func.count(Vulnerability.id))).scalar_one())


def get_vulnerability(db: Session, vulnerability_id: uuid.UUID) -> Vulnerability | None:
    return db.get(Vulnerability, vulnerability_id)
