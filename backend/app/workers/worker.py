"""Worker process: claims jobs from PostgreSQL and executes them.

Run with ``python -m app.workers.worker``. Multiple processes are safe thanks
to ``FOR UPDATE SKIP LOCKED``. A crashed worker's jobs are recovered on startup
and periodically via heartbeat expiry.
"""

from __future__ import annotations

import os
import signal
import socket
import sys
import time
import uuid
from types import FrameType

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import JobKind
from app.core.logging import configure_logging, get_logger, scan_id_var
from app.database.session import SessionLocal, engine
from app.modules.vulnerabilities.sync import sync_source
from app.workers import queue
from app.workers.models import Job
from app.workers.pipeline import execute_scan

logger = get_logger(__name__)

_shutdown = False


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    global _shutdown
    logger.info("shutdown signal received", extra={"extra_fields": {"signal": signum}})
    _shutdown = True


def worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}"


def _run_job(db: Session, job: Job, current_worker: str) -> None:
    payload = job.payload or {}
    heartbeat = lambda: queue.heartbeat(db, job.id)  # noqa: E731

    if job.kind == JobKind.SCAN.value:
        raw_scan_id = payload.get("scan_id")
        if not raw_scan_id:
            raise ValueError("SCAN job payload is missing scan_id")
        scan_id = uuid.UUID(str(raw_scan_id))
        scan_id_var.set(str(scan_id))
        try:
            execute_scan(db, scan_id, heartbeat=heartbeat)
        finally:
            scan_id_var.set(None)
        return

    if job.kind in {JobKind.SYNC_OSV.value, JobKind.SYNC_NVD.value, JobKind.SYNC_KEV.value}:
        source = {
            JobKind.SYNC_OSV.value: "OSV",
            JobKind.SYNC_NVD.value: "NVD",
            JobKind.SYNC_KEV.value: "CISA_KEV",
        }[job.kind]
        sync_source(db, source)
        return

    if job.kind == JobKind.SYNC_EPSS.value:
        from app.modules.vulnerabilities.sync import sync_epss

        sync_epss(db)
        return

    if job.kind == JobKind.AI_RISK.value:
        from app.modules.risk_analysis import service as risk_service

        raw = payload.get("finding_id")
        if not raw:
            raise ValueError("AI_RISK job payload is missing finding_id")
        risk_service.assess(db, uuid.UUID(str(raw)), principal="worker")
        return

    if job.kind == JobKind.AI_INVESTIGATE.value:
        from app.modules.ai.services import investigations

        raw = payload.get("finding_id")
        if not raw:
            raise ValueError("AI_INVESTIGATE job payload is missing finding_id")
        investigations.investigate(db, uuid.UUID(str(raw)), principal="worker")
        return

    if job.kind == JobKind.AI_REMEDIATE.value:
        from app.modules.remediation import service as remediation_service

        raw = payload.get("finding_id")
        if not raw:
            raise ValueError("AI_REMEDIATE job payload is missing finding_id")
        remediation_service.propose(db, uuid.UUID(str(raw)), principal="worker")
        return

    if job.kind == JobKind.AI_VERIFY.value:
        from app.modules.verification import service as verification_service

        raw = payload.get("verification_id")
        if not raw:
            raise ValueError("AI_VERIFY job payload is missing verification_id")
        verification_service.explain(db, uuid.UUID(str(raw)), principal="worker")
        return

    raise ValueError(f"Unsupported job kind: {job.kind}")


def run_once(current_worker: str) -> bool:
    """Claim and execute a single job. Returns True if a job was processed."""
    db = SessionLocal()
    try:
        job = queue.claim_next(db, current_worker)
        if job is None:
            return False
        try:
            _run_job(db, job, current_worker)
        except Exception as exc:
            db.rollback()
            logger.exception(
                "job execution failed",
                extra={"extra_fields": {"job_id": str(job.id), "kind": job.kind}},
            )
            queue.mark_failed(db, job.id, str(exc))
        else:
            queue.mark_succeeded(db, job.id)
        return True
    finally:
        db.close()


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    current_worker = worker_id()

    logger.info(
        "worker started",
        extra={"extra_fields": {"worker_id": current_worker, "pid": os.getpid()}},
    )

    with SessionLocal() as db:
        recovered = queue.recover_stale_jobs(db)
        if recovered:
            logger.info("stale jobs recovered at startup", extra={"extra_fields": {"count": recovered}})

    last_recovery = time.monotonic()
    while not _shutdown:
        processed = run_once(current_worker)
        if not processed:
            time.sleep(settings.worker_poll_seconds)
        if time.monotonic() - last_recovery > settings.job_stale_after_seconds / 2:
            with SessionLocal() as db:
                queue.recover_stale_jobs(db)
            last_recovery = time.monotonic()

    logger.info("worker stopped", extra={"extra_fields": {"worker_id": current_worker}})
    engine.dispose()
    return 0


if __name__ == "__main__":  # pragma: no cover - entrypoint
    sys.exit(main())
