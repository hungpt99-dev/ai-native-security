"""PostgreSQL-backed job queue.

Claims use ``FOR UPDATE SKIP LOCKED`` so multiple worker processes can run
safely. Retries use exponential backoff; jobs abandoned by a crashed worker
are reaped by ``recover_stale_jobs`` on worker startup and periodically.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import JobKind, JobStatus
from app.core.logging import get_logger
from app.workers.models import Job

logger = get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def enqueue(
    db: Session,
    kind: JobKind | str,
    payload: dict[str, Any] | None = None,
    *,
    priority: int = 100,
    run_after: datetime | None = None,
    max_attempts: int | None = None,
    schedule_id: uuid.UUID | None = None,
) -> Job:
    settings = get_settings()
    job = Job(
        kind=str(kind),
        payload=payload or {},
        status=JobStatus.QUEUED.value,
        priority=priority,
        run_after=run_after or _utcnow(),
        max_attempts=max_attempts or settings.job_max_attempts,
        schedule_id=schedule_id,
    )
    db.add(job)
    db.flush()
    logger.info(
        "job enqueued",
        extra={"extra_fields": {"job_id": str(job.id), "kind": job.kind}},
    )
    return job


def claim_next(db: Session, worker_id: str) -> Job | None:
    stmt = (
        select(Job)
        .where(Job.status == JobStatus.QUEUED.value, Job.run_after <= _utcnow())
        .order_by(Job.priority.asc(), Job.run_after.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    job = db.execute(stmt).scalar_one_or_none()
    if job is None:
        return None
    now = _utcnow()
    job.status = JobStatus.RUNNING.value
    job.attempts += 1
    job.locked_at = now
    job.heartbeat_at = now
    job.locked_by = worker_id
    db.commit()
    logger.info(
        "job claimed",
        extra={
            "extra_fields": {
                "job_id": str(job.id),
                "kind": job.kind,
                "attempt": job.attempts,
                "worker_id": worker_id,
            }
        },
    )
    return job


def heartbeat(db: Session, job_id: uuid.UUID) -> None:
    db.execute(
        update(Job).where(Job.id == job_id, Job.status == JobStatus.RUNNING.value).values(
            heartbeat_at=_utcnow()
        )
    )
    db.commit()


def mark_succeeded(db: Session, job_id: uuid.UUID) -> None:
    db.execute(
        update(Job)
        .where(Job.id == job_id)
        .values(status=JobStatus.SUCCEEDED.value, finished_at=_utcnow(), last_error=None)
    )
    db.commit()


def mark_failed(db: Session, job_id: uuid.UUID, error: str) -> None:
    """Record a failure, requeueing with backoff while attempts remain."""
    job = db.get(Job, job_id)
    if job is None:
        return
    job.last_error = error[:4000]
    if job.attempts < job.max_attempts:
        backoff = min(300, 10 * (2 ** (job.attempts - 1)))
        job.status = JobStatus.QUEUED.value
        job.run_after = _utcnow() + timedelta(seconds=backoff)
        job.locked_at = None
        job.locked_by = None
        logger.warning(
            "job failed, retry scheduled",
            extra={
                "extra_fields": {
                    "job_id": str(job.id),
                    "attempt": job.attempts,
                    "backoff_seconds": backoff,
                }
            },
        )
    else:
        job.status = JobStatus.FAILED.value
        job.finished_at = _utcnow()
        logger.error(
            "job failed permanently",
            extra={"extra_fields": {"job_id": str(job.id), "error": error[:500]}},
        )
    db.commit()


def cancel(db: Session, job_id: uuid.UUID) -> bool:
    job = db.get(Job, job_id)
    if job is None or job.status in {JobStatus.SUCCEEDED.value, JobStatus.FAILED.value}:
        return False
    job.status = JobStatus.CANCELED.value
    job.finished_at = _utcnow()
    db.commit()
    return True


def recover_stale_jobs(db: Session) -> int:
    """Requeue jobs whose worker died (heartbeat older than the stale window)."""
    settings = get_settings()
    cutoff = _utcnow() - timedelta(seconds=settings.job_stale_after_seconds)
    stale = db.execute(
        select(Job).where(
            Job.status == JobStatus.RUNNING.value,
            Job.heartbeat_at.is_not(None),
            Job.heartbeat_at < cutoff,
        )
    ).scalars().all()
    recovered = 0
    for job in stale:
        job.locked_at = None
        job.locked_by = None
        if job.attempts < job.max_attempts:
            job.status = JobStatus.QUEUED.value
            job.run_after = _utcnow()
        else:
            job.status = JobStatus.FAILED.value
            job.finished_at = _utcnow()
            job.last_error = job.last_error or "worker heartbeat expired"
        recovered += 1
    if recovered:
        db.commit()
        logger.warning(
            "recovered stale jobs", extra={"extra_fields": {"count": recovered}}
        )
    return recovered
