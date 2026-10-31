"""Scan lifecycle management.

The API only creates rows and enqueues jobs; all actual work happens in the
worker process. A partially unique index on ``(asset_id) WHERE status IN
('PENDING','RUNNING')`` guarantees one active scan per repository even under
concurrent requests.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.enums import (
    ACTIVE_SCAN_STATUSES,
    JobKind,
    JobStatus,
    ScanStatus,
    ScanTrigger,
)
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.modules.assets.models import Asset
from app.modules.scans.models import Scan, ScannerExecution
from app.workers.models import Job
from app.workers.queue import enqueue

logger = get_logger(__name__)


def active_scan_for_asset(db: Session, asset_id: uuid.UUID) -> Scan | None:
    return db.execute(
        select(Scan).where(Scan.asset_id == asset_id, Scan.status.in_(ACTIVE_SCAN_STATUSES))
    ).scalar_one_or_none()


def create_scan(
    db: Session,
    asset: Asset,
    *,
    trigger: ScanTrigger = ScanTrigger.MANUAL,
    requested_by: str | None = None,
) -> Scan:
    if active_scan_for_asset(db, asset.id):
        raise ConflictError(
            "A scan is already pending or running for this asset",
            details={"asset_id": str(asset.id)},
        )

    scan = Scan(
        asset_id=asset.id,
        status=ScanStatus.PENDING.value,
        trigger=trigger.value,
        branch=asset.default_branch,
        requested_by=requested_by,
    )
    db.add(scan)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("A scan is already pending or running for this asset") from exc

    asset.last_scan_status = ScanStatus.PENDING.value
    enqueue(db, JobKind.SCAN, {"scan_id": str(scan.id), "asset_id": str(asset.id)})
    db.flush()
    logger.info(
        "scan created",
        extra={
            "extra_fields": {
                "scan_id": str(scan.id),
                "asset_id": str(asset.id),
                "trigger": trigger.value,
            }
        },
    )
    return scan


def list_scans(
    db: Session,
    params: PageParams,
    *,
    asset_id: uuid.UUID | None = None,
    status: str | None = None,
    trigger: str | None = None,
) -> tuple[list[Scan], int]:
    stmt: Select = select(Scan)
    if asset_id:
        stmt = stmt.where(Scan.asset_id == asset_id)
    if status:
        stmt = stmt.where(Scan.status == status.upper())
    if trigger:
        stmt = stmt.where(Scan.trigger == trigger.upper())
    stmt = stmt.order_by(Scan.created_at.desc())
    return paginate(db, stmt, params)


def get_scan_or_404(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found", details={"scan_id": str(scan_id)})
    return scan


def cancel_scan(db: Session, scan: Scan) -> Scan:
    if scan.status not in ACTIVE_SCAN_STATUSES:
        raise ConflictError(
            "Only pending or running scans can be canceled",
            details={"status": scan.status},
        )
    now = datetime.now(UTC)
    scan.status = ScanStatus.CANCELED.value
    scan.finished_at = now
    scan.error_message = "Canceled by user"
    if scan.started_at:
        scan.duration_seconds = int((now - scan.started_at).total_seconds())

    running_job = db.execute(
        select(Job).where(
            Job.kind == JobKind.SCAN.value,
            Job.payload["scan_id"].astext == str(scan.id),
            Job.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
        )
    ).scalars().first()
    if running_job is not None:
        running_job.status = JobStatus.CANCELED.value
        running_job.finished_at = now

    asset = db.get(Asset, scan.asset_id)
    if asset is not None:
        asset.last_scan_status = ScanStatus.CANCELED.value
    db.flush()
    logger.info("scan canceled", extra={"extra_fields": {"scan_id": str(scan.id)}})
    return scan


def list_scanner_executions(db: Session, scan_id: uuid.UUID) -> list[ScannerExecution]:
    return list(
        db.execute(
            select(ScannerExecution)
            .where(ScannerExecution.scan_id == scan_id)
            .order_by(ScannerExecution.scanner)
        ).scalars()
    )


def get_scan_with_executions(db: Session, scan_id: uuid.UUID) -> Scan:
    return get_scan_or_404(db, scan_id)


def count_scans(db: Session, *, status: str | None = None) -> int:
    stmt = select(func.count(Scan.id))
    if status:
        stmt = stmt.where(Scan.status == status.upper())
    return int(db.execute(stmt).scalar_one())
