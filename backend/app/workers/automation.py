"""Policy boundary for automatic AI work.

Queueing AI analysis is a *policy* decision, not a module responsibility: the
scanner modules must stay runnable with AI disabled, and neither SBOM
reassessment nor the scan pipeline may import the AI layer directly. This helper
is the single place where "a new finding appeared, should we spend a model call"
is decided, and it is bounded by the same settings for both paths.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import ACTIVE_FINDING_STATUSES, SEVERITY_ORDER, JobKind, JobStatus, Severity
from app.core.logging import get_logger
from app.modules.findings.models import Finding
from app.workers import queue
from app.workers.models import Job

logger = get_logger(__name__)


def enqueue_auto_analysis(
    db: Session,
    finding_ids: Sequence[uuid.UUID],
    *,
    origin: str,
) -> int:
    """Queue contextual risk analysis for new findings, within policy limits.

    Only runs when ``ai_enabled`` and ``ai_auto_analyze`` are on, only for
    findings at or above ``ai_auto_analyze_min_severity``, and never more than
    ``ai_auto_analyze_max_findings`` per event. An AI failure therefore cannot
    break the deterministic path that queued it.
    """
    settings = get_settings()
    if not settings.ai_enabled or not settings.ai_auto_analyze or not finding_ids:
        return 0

    threshold = SEVERITY_ORDER.get(
        settings.ai_auto_analyze_min_severity.upper(), SEVERITY_ORDER[Severity.HIGH.value]
    )
    severities = [name for name, rank in SEVERITY_ORDER.items() if rank <= threshold]
    rows = db.execute(
        select(Finding)
        .where(
            Finding.id.in_(list(finding_ids)),
            Finding.status.in_(ACTIVE_FINDING_STATUSES),
            Finding.severity.in_(severities),
        )
        .order_by(Finding.cvss_score.desc().nullslast(), Finding.severity.asc())
        .limit(settings.ai_auto_analyze_max_findings)
    ).scalars().all()
    if not rows:
        return 0

    queued = 0
    for finding in rows:
        pending = db.execute(
            select(Job.id).where(
                Job.kind == JobKind.AI_RISK.value,
                Job.payload["finding_id"].astext == str(finding.id),
                Job.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
            )
        ).scalar_one_or_none()
        if pending:
            continue
        queue.enqueue(
            db,
            JobKind.AI_RISK,
            {"finding_id": str(finding.id), "asset_id": str(finding.asset_id)},
        )
        queued += 1
    db.commit()
    if queued:
        logger.info(
            "ai analysis queued",
            extra={"extra_fields": {"origin": origin, "queued": queued}},
        )
    return queued
