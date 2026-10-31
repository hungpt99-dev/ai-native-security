"""Finding queries and aggregate statistics."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import Select, case, func, or_, select
from sqlalchemy.orm import Session

from app.core.enums import SEVERITY_ORDER
from app.modules.findings.models import Finding


def findings_query(
    *,
    asset_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    scanners: Sequence[str] | None = None,
    severities: Sequence[str] | None = None,
    statuses: Sequence[str] | None = None,
    search: str | None = None,
    cve_id: str | None = None,
) -> Select:
    stmt: Select = select(Finding)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if scan_id:
        stmt = stmt.where(Finding.last_scan_id == scan_id)
    if scanners:
        stmt = stmt.where(Finding.scanner.in_([s.lower() for s in scanners]))
    if severities:
        stmt = stmt.where(Finding.severity.in_([s.upper() for s in severities]))
    if statuses:
        stmt = stmt.where(Finding.status.in_([s.upper() for s in statuses]))
    if cve_id:
        stmt = stmt.where(Finding.cve_id == cve_id.upper())
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Finding.title.ilike(pattern),
                Finding.rule_id.ilike(pattern),
                Finding.description.ilike(pattern),
                Finding.package_name.ilike(pattern),
                Finding.cve_id.ilike(pattern),
                Finding.file_path.ilike(pattern),
            )
        )
    return stmt


def severity_case():
    """CASE expression ordering severities from CRITICAL to UNKNOWN."""
    whens = [(SEVERITY_ORDER[sev], sev) for sev in SEVERITY_ORDER]
    return case({sev: rank for rank, sev in whens}, value=Finding.severity, else_=99)


def count_findings(
    db: Session,
    *,
    asset_id: uuid.UUID | None = None,
    statuses: Sequence[str] | None = None,
) -> int:
    stmt = select(func.count(Finding.id))
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if statuses:
        stmt = stmt.where(Finding.status.in_(list(statuses)))
    return int(db.execute(stmt).scalar_one())


def severity_counts(db: Session, *, asset_id: uuid.UUID | None = None) -> dict[str, int]:
    stmt = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    return {severity: int(count) for severity, count in db.execute(stmt).all()}


def scanner_counts(db: Session) -> list[tuple[str, int]]:
    stmt = (
        select(Finding.scanner, func.count(Finding.id))
        .group_by(Finding.scanner)
        .order_by(func.count(Finding.id).desc())
    )
    return [(scanner, int(count)) for scanner, count in db.execute(stmt).all()]


def status_counts(db: Session) -> dict[str, int]:
    stmt = select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    return {status: int(count) for status, count in db.execute(stmt).all()}


def active_findings_for_asset(db: Session, asset_id: uuid.UUID) -> list[Finding]:
    return list(
        db.execute(
            select(Finding).where(
                Finding.asset_id == asset_id,
                Finding.status.in_(["OPEN", "CONFIRMED", "ACCEPTED_RISK"]),
            )
        ).scalars()
    )


def top_risky_assets(db: Session, limit: int = 5) -> list[tuple[uuid.UUID, int]]:
    stmt = (
        select(Finding.asset_id, func.count(Finding.id).label("total"))
        .where(Finding.status.in_(["OPEN", "CONFIRMED"]))
        .where(Finding.severity.in_(["CRITICAL", "HIGH"]))
        .group_by(Finding.asset_id)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    )
    return [(asset_id, int(total)) for asset_id, total in db.execute(stmt).all()]
