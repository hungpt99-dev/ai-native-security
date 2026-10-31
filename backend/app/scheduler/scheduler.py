"""Scheduler process.

A single lightweight loop (``python -m app.scheduler``) that turns due
``schedules`` rows into queued jobs. PostgreSQL advisory locking guarantees
only one scheduler instance creates jobs, and each schedule row is updated in
the same transaction as the enqueue, so duplicate jobs cannot be emitted.
"""

from __future__ import annotations

import signal
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import FrameType

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import JobKind
from app.core.logging import configure_logging, get_logger
from app.database.session import SessionLocal, engine
from app.modules.assets.models import Asset
from app.workers import queue
from app.workers.models import Schedule

logger = get_logger(__name__)

ADVISORY_LOCK_KEY = 918273645
_shutdown = False


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    global _shutdown
    logger.info("scheduler shutdown signal", extra={"extra_fields": {"signal": signum}})
    _shutdown = True


def _now() -> datetime:
    return datetime.now(UTC)


def _upsert_schedule(
    db: Session,
    *,
    name: str,
    kind: JobKind,
    interval_seconds: int,
    payload: dict | None = None,
    enabled: bool = True,
) -> Schedule:
    schedule = db.execute(select(Schedule).where(Schedule.name == name)).scalar_one_or_none()
    if schedule is None:
        schedule = Schedule(
            name=name,
            kind=str(kind),
            payload=payload or {},
            interval_seconds=interval_seconds,
            enabled=enabled,
            next_run_at=_now(),
        )
        db.add(schedule)
    else:
        schedule.kind = str(kind)
        schedule.payload = payload or {}
        schedule.interval_seconds = interval_seconds
        schedule.enabled = enabled
        if schedule.next_run_at is None:
            schedule.next_run_at = _now()
    db.flush()
    return schedule


def sync_asset_schedules(db: Session) -> int:
    """Create/refresh one scan schedule per monitored asset."""
    settings = get_settings()
    assets = db.execute(select(Asset).where(Asset.monitoring_enabled.is_(True))).scalars().all()
    active_names: set[str] = set()
    for asset in assets:
        minutes = asset.scan_interval_minutes or settings.scanner_schedule_interval_minutes
        name = f"asset-scan:{asset.id}"
        active_names.add(name)
        _upsert_schedule(
            db,
            name=name,
            kind=JobKind.SCAN,
            interval_seconds=max(300, minutes * 60),
            payload={"asset_id": str(asset.id)},
        )
    # Disable schedules for assets that are no longer monitored.
    for schedule in db.execute(select(Schedule).where(Schedule.name.like("asset-scan:%"))).scalars():
        if schedule.name not in active_names:
            schedule.enabled = False
    db.commit()
    return len(active_names)


def ensure_default_schedules(db: Session) -> None:
    settings = get_settings()
    if settings.vuln_sync_enabled:
        _upsert_schedule(
            db,
            name="sync:osv",
            kind=JobKind.SYNC_OSV,
            interval_seconds=max(600, settings.osv_sync_interval_minutes * 60),
        )
        _upsert_schedule(
            db,
            name="sync:nvd",
            kind=JobKind.SYNC_NVD,
            interval_seconds=max(900, settings.nvd_sync_interval_minutes * 60),
        )
        _upsert_schedule(
            db,
            name="sync:kev",
            kind=JobKind.SYNC_KEV,
            interval_seconds=max(600, settings.kev_sync_interval_minutes * 60),
        )
    if settings.epss_enabled:
        _upsert_schedule(
            db,
            name="sync:epss",
            kind=JobKind.SYNC_EPSS,
            interval_seconds=max(1800, settings.epss_sync_interval_minutes * 60),
        )
    # Policies are data; seeding them here keeps a fresh install usable without a
    # manual step and without writing during a read path.
    from app.modules.security_policies.service import ensure_defaults

    ensure_defaults(db)
    db.commit()


def claim_due_schedules(db: Session, limit: int = 20) -> list[Schedule]:
    """Lock due schedules and enqueue their jobs atomically."""
    due = db.execute(
        select(Schedule)
        .where(Schedule.enabled.is_(True), Schedule.next_run_at <= _now())
        .order_by(Schedule.next_run_at.asc())
        .limit(limit)
        .with_for_update(skip_locked=True)
    ).scalars().all()

    for schedule in due:
        now = _now()
        payload = dict(schedule.payload or {})
        try:
            if schedule.kind == JobKind.SCAN.value:
                raw_asset_id = payload.get("asset_id")
                asset = db.get(Asset, uuid.UUID(str(raw_asset_id))) if raw_asset_id else None
                if asset is None or not asset.monitoring_enabled:
                    schedule.enabled = False
                    schedule.last_status = "SKIPPED"
                    schedule.last_error = "Asset missing or monitoring disabled"
                    continue
                # Reuse the same guard as the API: one active scan per asset.
                from app.modules.scans.service import active_scan_for_asset

                if active_scan_for_asset(db, asset.id) is not None:
                    schedule.last_status = "SKIPPED"
                    schedule.last_error = "Scan already active"
                    schedule.next_run_at = now + timedelta(seconds=schedule.interval_seconds)
                    continue
                from app.core.enums import ScanTrigger
                from app.modules.scans.service import create_scan

                scan = create_scan(db, asset, trigger=ScanTrigger.SCHEDULED, requested_by="scheduler")
                schedule.last_job_id = None
                schedule.last_status = scan.status
                schedule.last_error = None
                payload = {**payload, "scan_id": str(scan.id)}
            else:
                job = queue.enqueue(db, schedule.kind, payload, schedule_id=schedule.id)
                schedule.last_job_id = job.id
                schedule.last_status = "QUEUED"
                schedule.last_error = None
            schedule.last_run_at = now
            schedule.next_run_at = now + timedelta(seconds=schedule.interval_seconds)
        except Exception as exc:  # keep the scheduler alive on bad rows
            schedule.last_status = "FAILED"
            schedule.last_error = str(exc)[:1000]
            schedule.next_run_at = now + timedelta(seconds=min(300, schedule.interval_seconds))
            logger.exception(
                "failed to enqueue scheduled job",
                extra={"extra_fields": {"schedule": schedule.name}},
            )
    db.commit()
    return list(due)


def tick(db: Session) -> int:
    claim_due_schedules(db)
    return len(
        db.execute(
            select(Schedule.id).where(Schedule.enabled.is_(True), Schedule.next_run_at <= _now())
        ).all()
    )


def run_forever() -> int:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    logger.info("scheduler started", extra={"extra_fields": {"enabled": settings.scheduler_enabled}})

    with SessionLocal() as db:
        locked = db.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": ADVISORY_LOCK_KEY}).scalar()
        if not locked:
            logger.warning("scheduler advisory lock is held by another instance; exiting")
            return 0
        try:
            ensure_default_schedules(db)
            sync_asset_schedules(db)
            last_asset_sync = time.monotonic()
            while not _shutdown:
                claim_due_schedules(db)
                if time.monotonic() - last_asset_sync > 300:
                    sync_asset_schedules(db)
                    last_asset_sync = time.monotonic()
                time.sleep(settings.scheduler_poll_seconds)
        finally:
            db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": ADVISORY_LOCK_KEY})
            db.commit()
    engine.dispose()
    logger.info("scheduler stopped")
    return 0


def main() -> int:
    return run_forever()


if __name__ == "__main__":  # pragma: no cover - entrypoint
    raise SystemExit(main())
