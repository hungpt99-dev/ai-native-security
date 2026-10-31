"""Vulnerability intelligence HTTP API."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.enums import JobKind, JobStatus, VulnerabilitySource
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.pagination import Page, PageParams, page_params, paginate
from app.database.session import get_db
from app.modules.vulnerabilities import repository as vuln_repo
from app.modules.vulnerabilities.models import Vulnerability, VulnerabilitySyncHistory
from app.modules.vulnerabilities.schemas import (
    IntelligenceStats,
    SyncHistoryRead,
    SyncTriggerResponse,
    VulnerabilityDetail,
    VulnerabilityRead,
)
from app.workers import queue
from app.workers.models import Job

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("/stats", response_model=IntelligenceStats)
def intelligence_stats(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> IntelligenceStats:
    total = vuln_repo.count_vulnerabilities(db)
    kev = int(
        db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.source == VulnerabilitySource.CISA_KEV.value
            )
        ).scalar_one()
    )
    by_source = {
        source: int(count)
        for source, count in db.execute(
            select(Vulnerability.source, func.count(Vulnerability.id)).group_by(Vulnerability.source)
        ).all()
    }
    by_severity = {
        severity: int(count)
        for severity, count in db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(
                Vulnerability.severity
            )
        ).all()
    }
    last_sync: dict[str, str | None] = {}
    for source in VulnerabilitySource:
        entry = vuln_repo.last_successful_sync(db, source.value)
        last_sync[source.value] = entry.finished_at.isoformat() if entry and entry.finished_at else None
    return IntelligenceStats(
        total=total, kev=kev, by_source=by_source, by_severity=by_severity, last_sync=last_sync
    )


@router.get("/sync/history", response_model=Page[SyncHistoryRead])
def sync_history(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    source: Annotated[str | None, Query()] = None,
) -> Page[SyncHistoryRead]:
    stmt: Select = select(VulnerabilitySyncHistory)
    if source:
        stmt = stmt.where(VulnerabilitySyncHistory.source == source.upper())
    stmt = stmt.order_by(VulnerabilitySyncHistory.started_at.desc())
    rows, total = paginate(db, stmt, params)
    return Page.build([SyncHistoryRead.model_validate(row) for row in rows], total, params)


@router.post("/sync/{source}", response_model=SyncTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_sync(
    source: str,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> SyncTriggerResponse:
    key = source.upper()
    kinds = {
        VulnerabilitySource.OSV.value: JobKind.SYNC_OSV,
        VulnerabilitySource.NVD.value: JobKind.SYNC_NVD,
        VulnerabilitySource.CISA_KEV.value: JobKind.SYNC_KEV,
    }
    if key not in kinds:
        raise ValidationError(
            "Unknown intelligence source", details={"allowed": sorted(kinds)}
        )
    running = db.execute(
        select(Job).where(
            Job.kind == kinds[key].value,
            Job.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
        )
    ).scalars().first()
    if running is not None:
        raise ConflictError(
            "A synchronization for this source is already queued or running",
            details={"job_id": str(running.id)},
        )
    job = queue.enqueue(db, kinds[key], {"requested_by": principal.subject})
    db.commit()
    return SyncTriggerResponse(job_id=job.id, source=key, status=job.status)


@router.get("", response_model=Page[VulnerabilityRead])
def list_vulnerabilities(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    search: Annotated[str | None, Query(max_length=200)] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    source: Annotated[str | None, Query()] = None,
    kev_only: Annotated[bool, Query()] = False,
) -> Page[VulnerabilityRead]:
    stmt: Select = select(Vulnerability)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Vulnerability.source_id.ilike(pattern),
                Vulnerability.cve_id.ilike(pattern),
                Vulnerability.summary.ilike(pattern),
            )
        )
    if severity:
        stmt = stmt.where(Vulnerability.severity.in_([s.upper() for s in severity]))
    if source:
        stmt = stmt.where(Vulnerability.source == source.upper())
    if kev_only:
        stmt = stmt.where(Vulnerability.is_kev.is_(True))
    stmt = stmt.order_by(Vulnerability.modified_at.desc().nullslast())
    rows, total = paginate(db, stmt, params)
    return Page.build([VulnerabilityRead.model_validate(row) for row in rows], total, params)


@router.get("/{vulnerability_id}", response_model=VulnerabilityDetail)
def get_vulnerability(
    vulnerability_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> VulnerabilityDetail:
    row = db.get(Vulnerability, vulnerability_id)
    if row is None:
        raise NotFoundError(
            "Vulnerability not found", details={"vulnerability_id": str(vulnerability_id)}
        )
    return VulnerabilityDetail.model_validate(row)
