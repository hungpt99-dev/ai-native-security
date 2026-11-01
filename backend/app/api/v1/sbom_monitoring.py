"""API for the continuous SBOM lifecycle.

Endpoints are additive: the existing ``/sboms`` and ``/assets/{id}/sboms``
resources keep their contracts (they only gained new fields), and everything new
lives under ``/assets/{id}/sbom/...``, ``/sboms/{id}/diff`` and
``/sbom/monitoring/...``.

Read endpoints never mutate rows. Action endpoints only enqueue jobs and answer
202 — the request path never checks out a repository or runs a scanner.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.errors import ValidationError
from app.core.pagination import MAX_PAGE_SIZE, Page, PageParams, page_params, paginate
from app.database.session import get_db
from app.modules.sbom import lifecycle, service
from app.modules.sbom.diff import diff_packages
from app.modules.sbom.models import SbomMonitoringRun

router = APIRouter(tags=["sbom"])


class MonitoringRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    sbom_id: uuid.UUID | None
    job_id: uuid.UUID | None
    kind: str
    trigger: str
    status: str
    outcome: str | None
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int | None
    head_commit_sha: str | None
    previous_commit_sha: str | None
    branch: str | None
    dependency_fingerprint: str | None
    previous_dependency_fingerprint: str | None
    components_evaluated: int
    findings_created: int
    findings_updated: int
    findings_resolved: int
    new_kev_findings: int
    failure_count: int
    skipped_reason: str | None
    error_message: str | None
    metrics: dict[str, Any]


class ComponentChangeRead(BaseModel):
    change: str
    identity: str
    identity_basis: str
    name: str
    ecosystem: str | None
    purl: str | None
    version_before: str | None
    version_after: str | None
    is_direct_before: bool | None
    is_direct_after: bool | None


class SbomDiffRead(BaseModel):
    previous_sbom_id: str | None
    current_sbom_id: str | None
    added: int
    removed: int
    version_changed: int
    unchanged: int
    changed: int
    total_previous: int
    total_current: int
    items: list[ComponentChangeRead]
    total: int
    page: int
    page_size: int
    pages: int


class ActionAccepted(BaseModel):
    asset_id: uuid.UUID
    job_id: uuid.UUID | None
    deduplicated: bool
    kind: str
    sbom_id: uuid.UUID | None = None


def _enqueue_result(
    asset_id: uuid.UUID, job: Any, created: bool, kind: str, sbom_id: uuid.UUID | None = None
) -> ActionAccepted:
    return ActionAccepted(
        asset_id=asset_id,
        job_id=job.id if job is not None else None,
        deduplicated=not created,
        kind=kind,
        sbom_id=sbom_id,
    )


@router.get("/assets/{asset_id}/sbom/status")
def get_sbom_status(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    """Snapshot overview, freshness, monitoring state and the next evaluation."""
    return lifecycle.asset_monitoring_status(db, asset_id)


@router.post(
    "/assets/{asset_id}/sbom/check",
    response_model=ActionAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
def trigger_dependency_check(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ActionAccepted:
    """Refresh dependency status (provider metadata only, no clone)."""
    asset = lifecycle.require_asset(db, asset_id)
    job, created = lifecycle.enqueue_check(db, asset, trigger="MANUAL")
    db.commit()
    return _enqueue_result(asset.id, job, created, "SBOM_CHANGE_CHECK")


@router.post(
    "/assets/{asset_id}/sbom/generate",
    response_model=ActionAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
def trigger_sbom_generation(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ActionAccepted:
    """Generate a new snapshot (checkout + Syft only — not a full scan)."""
    asset = lifecycle.require_asset(db, asset_id)
    job, created = lifecycle.enqueue_generation(db, asset, trigger="MANUAL")
    db.commit()
    return _enqueue_result(asset.id, job, created, "SBOM_GENERATE")


@router.post(
    "/assets/{asset_id}/sbom/reassess",
    response_model=ActionAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
def trigger_reassessment(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    sbom_id: Annotated[uuid.UUID | None, Query()] = None,
) -> ActionAccepted:
    """Re-evaluate stored inventory against stored intelligence."""
    asset = lifecycle.require_asset(db, asset_id)
    if sbom_id is not None:
        lifecycle.validate_snapshot_belongs(db, asset.id, sbom_id)
    job, created = lifecycle.enqueue_reassessment(
        db, asset, sbom_id=sbom_id, trigger="MANUAL"
    )
    db.commit()
    return _enqueue_result(asset.id, job, created, "SBOM_VULNERABILITY_REASSESSMENT", sbom_id)


@router.get(
    "/assets/{asset_id}/sbom/monitoring-runs", response_model=Page[MonitoringRunRead]
)
def list_monitoring_runs(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    kind: Annotated[str | None, Query(max_length=32)] = None,
    run_status: Annotated[str | None, Query(alias="status", max_length=16)] = None,
) -> Page[MonitoringRunRead]:
    """Dependency checks, generations and reassessments for one asset."""
    lifecycle.require_asset(db, asset_id)
    stmt: Select = select(SbomMonitoringRun).where(SbomMonitoringRun.asset_id == asset_id)
    if kind:
        stmt = stmt.where(SbomMonitoringRun.kind == kind.upper())
    if run_status:
        stmt = stmt.where(SbomMonitoringRun.status == run_status.upper())
    stmt = stmt.order_by(SbomMonitoringRun.started_at.desc())
    rows, total = paginate(db, stmt, params)
    return Page.build([MonitoringRunRead.model_validate(row) for row in rows], total, params)


@router.get("/sboms/{sbom_id}/diff", response_model=SbomDiffRead)
def compare_snapshots(
    sbom_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    against: Annotated[uuid.UUID | None, Query()] = None,
    change: Annotated[str | None, Query(max_length=24)] = None,
) -> SbomDiffRead:
    """Deterministic component diff between two snapshots.

    ``against`` defaults to the snapshot this one replaced. ``change`` filters
    to ADDED / REMOVED / VERSION_CHANGED / UNCHANGED; the default returns only
    the actual differences, with unchanged components available on request.
    """
    current = service.get_sbom_or_404(db, sbom_id)
    if against is None:
        previous = service.previous_snapshot(db, current)
    else:
        previous = service.get_sbom_or_404(db, against)
        if previous.asset_id != current.asset_id:
            raise ValidationError(
                "Snapshots belong to different assets",
                details={"current_asset": str(current.asset_id)},
            )
    previous_packages = service.packages_for_sbom(db, previous.id) if previous else []
    current_packages = service.packages_for_sbom(db, current.id)
    diff = diff_packages(
        previous_packages,
        current_packages,
        previous_sbom_id=str(previous.id) if previous else None,
        current_sbom_id=str(current.id),
    )
    selected = diff.filter(change)
    start = params.offset
    end = start + min(params.page_size, MAX_PAGE_SIZE)
    window = selected[start:end]
    pages = (len(selected) + params.page_size - 1) // params.page_size if params.page_size else 0
    return SbomDiffRead(
        previous_sbom_id=diff.previous_sbom_id,
        current_sbom_id=diff.current_sbom_id,
        added=diff.added,
        removed=diff.removed,
        version_changed=diff.version_changed,
        unchanged=diff.unchanged,
        changed=diff.changed,
        total_previous=diff.total_previous,
        total_current=diff.total_current,
        items=[ComponentChangeRead(**vars(entry)) for entry in window],
        total=len(selected),
        page=params.page,
        page_size=params.page_size,
        pages=pages,
    )


@router.get("/sbom/monitoring/summary")
def monitoring_summary(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> dict[str, Any]:
    """Operational counters, including the estimated full scans avoided."""
    return lifecycle.monitoring_summary(db, days=days)
