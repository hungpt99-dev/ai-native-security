"""Finding lifecycle: deduplication, history and status transitions.

Rules enforced here:
* deduplication by ``(asset_id, fingerprint)`` — never by scanner ids;
* history rows record detection, redetection, manual transitions and
  automatic resolution;
* automatic resolution only happens through ``resolve_missing_findings``,
  which the pipeline calls *only* after a successful scan.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    ALLOWED_FINDING_TRANSITIONS,
    FindingEvent,
    FindingStatus,
)
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.modules.findings.models import Finding, FindingHistory
from app.modules.findings.repository import findings_query, severity_case
from app.modules.scanners.base import NormalizedFinding

logger = get_logger(__name__)

_SORT_COLUMNS = {
    "last_detected_at": lambda: Finding.last_detected_at,
    "first_detected_at": lambda: Finding.first_detected_at,
    "severity": severity_case,
    "cvss_score": lambda: Finding.cvss_score,
    "title": lambda: Finding.title,
    "status": lambda: Finding.status,
}


def _now() -> datetime:
    return datetime.now(UTC)


def list_findings(
    db: Session,
    params: PageParams,
    *,
    asset_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    scanners: Sequence[str] | None = None,
    severities: Sequence[str] | None = None,
    statuses: Sequence[str] | None = None,
    search: str | None = None,
    cve_id: str | None = None,
    sort_by: str = "severity",
    sort_order: str = "asc",
) -> tuple[list[Finding], int]:
    stmt = findings_query(
        asset_id=asset_id,
        scan_id=scan_id,
        scanners=scanners,
        severities=severities,
        statuses=statuses,
        search=search,
        cve_id=cve_id,
    )
    column_factory = _SORT_COLUMNS.get(sort_by, _SORT_COLUMNS["severity"])
    column = column_factory()
    if sort_by == "severity" and sort_order.lower() == "desc":
        column = column.desc()
    elif sort_order.lower() == "asc":
        column = column.asc()
    else:
        column = column.desc()
    stmt = stmt.order_by(column, Finding.last_detected_at.desc())
    return paginate(db, stmt, params)


def get_finding_or_404(db: Session, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError("Finding not found", details={"finding_id": str(finding_id)})
    return finding


def history_for_finding(db: Session, finding_id: uuid.UUID) -> list[FindingHistory]:
    return list(
        db.execute(
            select(FindingHistory)
            .where(FindingHistory.finding_id == finding_id)
            .order_by(FindingHistory.created_at.desc())
        ).scalars()
    )


def record_scan_findings(
    db: Session,
    *,
    asset_id: uuid.UUID,
    scan_id: uuid.UUID,
    normalized: Sequence[NormalizedFinding],
) -> dict[str, int]:
    """Upsert normalized scanner findings for a completed scan stage.

    Returns counts of created / updated / reopened findings.
    """
    now = _now()
    created = updated = reopened = 0

    # Existing findings for the asset, keyed by fingerprint, in one query.
    existing_rows = db.execute(
        select(Finding).where(Finding.asset_id == asset_id)
    ).scalars().all()
    existing = {row.fingerprint: row for row in existing_rows}

    for item in normalized:
        fingerprint = item.fingerprint or item.compute_fingerprint(asset_id)
        metadata = dict(item.metadata or {})
        row = existing.get(fingerprint)
        if row is None:
            row = Finding(
                asset_id=asset_id,
                first_scan_id=scan_id,
                last_scan_id=scan_id,
                scanner=item.scanner,
                rule_id=item.rule_id or "",
                title=item.title or item.rule_id or "Finding",
                description=item.description,
                category=item.category,
                severity=item.severity,
                file_path=item.file_path,
                line_number=item.line_number,
                package_name=item.package_name,
                package_version=item.package_version,
                purl=item.purl,
                cve_id=item.cve_id,
                cvss_score=item.cvss_score,
                status=FindingStatus.OPEN.value,
                fingerprint=fingerprint,
                metadata_json=metadata,
                first_detected_at=now,
                last_detected_at=now,
            )
            db.add(row)
            db.flush()
            db.add(
                FindingHistory(
                    finding_id=row.id,
                    scan_id=scan_id,
                    event=FindingEvent.DETECTED.value,
                    to_status=FindingStatus.OPEN.value,
                    actor="scanner",
                    note=f"Detected by {item.scanner}",
                )
            )
            existing[fingerprint] = row
            created += 1
            continue

        previous_status = row.status
        row.last_scan_id = scan_id
        row.last_detected_at = now
        row.severity = item.severity or row.severity
        row.title = item.title or row.title
        row.description = item.description or row.description
        row.metadata_json = {**(row.metadata_json or {}), **metadata}
        row.cve_id = row.cve_id or item.cve_id
        row.cvss_score = item.cvss_score if item.cvss_score is not None else row.cvss_score
        row.purl = row.purl or item.purl

        if previous_status == FindingStatus.RESOLVED.value:
            row.status = FindingStatus.OPEN.value
            row.resolved_at = None
            db.add(
                FindingHistory(
                    finding_id=row.id,
                    scan_id=scan_id,
                    event=FindingEvent.REOPENED.value,
                    from_status=previous_status,
                    to_status=row.status,
                    actor="scanner",
                    note="Finding reappeared in a later scan",
                )
            )
            reopened += 1
        elif previous_status in {FindingStatus.FALSE_POSITIVE.value}:
            # A subsequent scan detecting it again is new evidence: reopen.
            row.status = FindingStatus.OPEN.value
            db.add(
                FindingHistory(
                    finding_id=row.id,
                    scan_id=scan_id,
                    event=FindingEvent.REOPENED.value,
                    from_status=previous_status,
                    to_status=row.status,
                    actor="scanner",
                    note="Finding re-detected after being marked false positive",
                )
            )
            reopened += 1
        else:
            updated += 1

    db.flush()
    logger.info(
        "findings recorded",
        extra={
            "extra_fields": {
                "scan_id": str(scan_id),
                "asset_id": str(asset_id),
                "created": created,
                "updated": updated,
                "reopened": reopened,
            }
        },
    )
    return {"created": created, "updated": updated, "reopened": reopened}


def resolve_missing_findings(
    db: Session,
    *,
    asset_id: uuid.UUID,
    scan_id: uuid.UUID,
    scanners: Sequence[str] | None = None,
) -> int:
    """Mark active findings not detected by ``scan_id`` as RESOLVED.

    Must only be called when a scan completed successfully, and only for the
    scanners that actually ran: callers pass ``scanners`` so findings owned by
    a failed or skipped scanner are never resolved by accident.
    """
    now = _now()
    stmt = select(Finding).where(
        Finding.asset_id == asset_id,
        Finding.status.in_(ACTIVE_FINDING_STATUSES),
        Finding.last_scan_id != scan_id,
    )
    if scanners is not None:
        stmt = stmt.where(Finding.scanner.in_(list(scanners)))
    rows = db.execute(stmt).scalars().all()
    for row in rows:
        row.status = FindingStatus.RESOLVED.value
        row.resolved_at = now
        db.add(
            FindingHistory(
                finding_id=row.id,
                scan_id=scan_id,
                event=FindingEvent.AUTO_RESOLVED.value,
                from_status=FindingStatus.OPEN.value,
                to_status=FindingStatus.RESOLVED.value,
                actor="system",
                note="Not detected in the latest successful scan",
            )
        )
    db.flush()
    if rows:
        logger.info(
            "findings auto-resolved",
            extra={"extra_fields": {"scan_id": str(scan_id), "count": len(rows)}},
        )
    return len(rows)


def update_status(
    db: Session,
    finding: Finding,
    new_status: str,
    *,
    actor: str = "api",
    note: str | None = None,
) -> Finding:
    target = new_status.upper()
    if target not in {status.value for status in FindingStatus}:
        raise ValidationError("Unknown finding status", details={"status": new_status})
    previous = finding.status
    if target == previous:
        return finding

    allowed = ALLOWED_FINDING_TRANSITIONS.get(previous, set())
    if target not in allowed:
        raise ConflictError(
            "Invalid status transition",
            details={"from": previous, "to": target, "allowed": sorted(allowed)},
        )

    finding.status = target
    finding.resolved_at = _now() if target == FindingStatus.RESOLVED.value else None
    db.add(
        FindingHistory(
            finding_id=finding.id,
            event=FindingEvent.STATUS_CHANGED.value,
            from_status=previous,
            to_status=target,
            actor=actor,
            note=note,
        )
    )
    db.flush()
    return finding


def scan_summary(db: Session, scan_id: uuid.UUID) -> dict[str, int]:
    """Severity counts for findings detected by a specific scan."""
    rows = db.execute(
        select(Finding.severity, Finding.status).where(Finding.last_scan_id == scan_id)
    ).all()
    summary: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0,
    }
    for severity, _status in rows:
        summary[severity] = summary.get(severity, 0) + 1
    summary["total"] = len(rows)
    return summary


def anchor_metadata(finding: Finding, key: str, value: Any) -> None:
    """Merge a single metadata key (used for intel enrichment)."""
    metadata = dict(finding.metadata_json or {})
    metadata[key] = value
    finding.metadata_json = metadata
