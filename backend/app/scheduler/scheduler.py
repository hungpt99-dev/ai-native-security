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
RUNTIME_ANOMALY_SCHEDULE = "runtime:anomaly"
INFRA_SCHEDULE_PREFIX = "asset-infra-scan:"
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
    """Create/refresh one scan schedule and one SBOM check schedule per asset.

    Full scans and lightweight dependency checks are deliberately separate
    schedules: monitoring composition must not require a full scan, and its
    interval is independent (and much shorter) than the scan interval.
    """
    settings = get_settings()
    from app.modules.sbom.lifecycle import DEPENDENCY_CHECK_SCHEDULE_PREFIX

    assets = db.execute(select(Asset).where(Asset.monitoring_enabled.is_(True))).scalars().all()
    active_names: set[str] = set()
    active_check_names: set[str] = set()
    active_infra_names: set[str] = set()
    for asset in assets:
        # Repository scanning and SBOM monitoring only apply to repository
        # assets. A container image has no branch, no clone and no SBOM update
        # path; it is covered by the infrastructure schedule below.
        if asset.kind == "REPOSITORY":
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
            check_name = f"{DEPENDENCY_CHECK_SCHEDULE_PREFIX}{asset.id}"
            active_check_names.add(check_name)
            _upsert_schedule(
                db,
                name=check_name,
                kind=JobKind.SBOM_CHANGE_CHECK,
                interval_seconds=max(300, settings.sbom_dependency_check_interval_minutes * 60),
                payload={"asset_id": str(asset.id), "trigger": "SCHEDULED"},
                enabled=settings.sbom_monitoring_enabled,
            )
        # Infrastructure assessment is opt-in per repository (an interval must be
        # set) and automatic for container images, which have no other coverage.
        infra_scanner = (
            "trivy-image" if asset.kind == "CONTAINER_IMAGE" else "trivy-config"
        )
        wants_infra = settings.infrastructure_enabled and (
            asset.kind == "CONTAINER_IMAGE"
            or (asset.kind == "REPOSITORY" and asset.infra_scan_interval_minutes is not None)
        )
        if wants_infra:
            infra_name = f"{INFRA_SCHEDULE_PREFIX}{asset.id}"
            active_infra_names.add(infra_name)
            _upsert_schedule(
                db,
                name=infra_name,
                kind=JobKind.INFRA_SCAN,
                interval_seconds=max(
                    300,
                    (asset.infra_scan_interval_minutes
                     or settings.infrastructure_scan_interval_minutes) * 60,
                ),
                payload={
                    "asset_id": str(asset.id),
                    "scanner": infra_scanner,
                    "trigger": "SCHEDULED",
                },
            )
    # Disable schedules for assets that are no longer monitored.
    for schedule in db.execute(select(Schedule).where(Schedule.name.like("asset-scan:%"))).scalars():
        if schedule.name not in active_names:
            schedule.enabled = False
    for schedule in db.execute(
        select(Schedule).where(Schedule.name.like(f"{DEPENDENCY_CHECK_SCHEDULE_PREFIX}%"))
    ).scalars():
        if schedule.name not in active_check_names:
            schedule.enabled = False
    for schedule in db.execute(
        select(Schedule).where(Schedule.name.like(f"{INFRA_SCHEDULE_PREFIX}%"))
    ).scalars():
        if schedule.name not in active_infra_names:
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
    # Continuous vulnerability monitoring: one global job re-evaluates every
    # stored snapshot. It never enqueues a scan and never touches a repository.
    from app.modules.sbom.lifecycle import REASSESSMENT_SCHEDULE_NAME

    _upsert_schedule(
        db,
        name=REASSESSMENT_SCHEDULE_NAME,
        kind=JobKind.SBOM_VULNERABILITY_REASSESSMENT,
        interval_seconds=max(3600, settings.sbom_reassessment_interval_minutes * 60),
        payload={"trigger": "SCHEDULED"},
        enabled=settings.sbom_monitoring_enabled,
    )
    # Deterministic event-rate anomaly pass. It reads stored events only.
    _upsert_schedule(
        db,
        name=RUNTIME_ANOMALY_SCHEDULE,
        kind=JobKind.RUNTIME_ANOMALY_SCAN,
        interval_seconds=max(3600, settings.events_anomaly_interval_minutes * 60),
        payload={"trigger": "SCHEDULED"},
        enabled=settings.events_anomaly_enabled,
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
            elif schedule.kind == JobKind.INFRA_SCAN.value:
                raw_asset_id = payload.get("asset_id")
                asset = db.get(Asset, uuid.UUID(str(raw_asset_id))) if raw_asset_id else None
                if asset is None or not asset.monitoring_enabled:
                    schedule.enabled = False
                    schedule.last_status = "SKIPPED"
                    schedule.last_error = "Asset missing or monitoring disabled"
                    continue
                from app.core.errors import ConflictError
                from app.modules.infrastructure import service as infra_service

                scanner = str(payload.get("scanner") or "trivy-config")
                try:
                    target_kind = (
                        "CONTAINER_IMAGE"
                        if asset.kind == "CONTAINER_IMAGE"
                        else "IAC_REPOSITORY"
                    )
                    row = infra_service.create_scan(
                        db,
                        target_kind=target_kind,
                        scanner=scanner,
                        asset_id=asset.id if asset.kind != "CONTAINER_IMAGE" else None,
                        target_ref=(
                            (asset.external_ref or "").removeprefix("docker://")
                            if asset.kind == "CONTAINER_IMAGE"
                            else None
                        ),
                        requested_by="scheduler",
                        trigger="SCHEDULED",
                    )
                except ConflictError:
                    schedule.last_status = "SKIPPED"
                    schedule.last_error = "Assessment already active"
                    schedule.next_run_at = now + timedelta(seconds=schedule.interval_seconds)
                    continue
                schedule.last_job_id = None
                schedule.last_status = row.status
                schedule.last_error = None
            else:
                # Idempotent enqueue: a periodic job that is already pending for
                # the same target must not be queued twice.
                match = (
                    {"asset_id": str(payload["asset_id"])} if payload.get("asset_id") else {}
                )
                job, created = queue.enqueue_once(
                    db,
                    schedule.kind,
                    payload,
                    match=match,
                    schedule_id=schedule.id,
                )
                schedule.last_job_id = job.id if job else None
                schedule.last_status = "QUEUED" if created else "DEDUPLICATED"
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
