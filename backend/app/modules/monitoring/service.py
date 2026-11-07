"""Monitoring health and platform overview.

Health is derived from evidence in the database: when did monitoring last
succeed, how old is the intelligence, is the queue moving. A component with no
evidence is ``UNKNOWN``, never ``HEALTHY`` — the platform does not claim a
control works because it has not failed yet.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    ACTIVE_INCIDENT_STATUSES,
    JobStatus,
    ScanStatus,
    Severity,
)
from app.modules.ai.providers.registry import provider_status
from app.modules.assets.models import Asset
from app.modules.events.models import DetectionRule, SecurityEvent
from app.modules.findings.models import Finding
from app.modules.incidents.models import Incident
from app.modules.infrastructure.models import InfrastructureScan
from app.modules.sbom.models import SbomMonitoringRun
from app.modules.vulnerabilities.models import VulnerabilityEpss, VulnerabilitySyncHistory

#: Freshness policy. These are explicit service-level expectations, not
#: preferences: a source older than its window is reported STALE.
FRESHNESS_WINDOWS: dict[str, timedelta] = {
    "OSV": timedelta(hours=24),
    "NVD": timedelta(hours=48),
    "CISA_KEV": timedelta(hours=48),
    "EPSS": timedelta(hours=48),
}

_STATUS_RANK = {"HEALTHY": 1, "UNKNOWN": 2, "DEGRADED": 3, "DISABLED": 0}


def _now() -> datetime:
    return datetime.now(UTC)


def _component(status: str, **detail: Any) -> dict[str, Any]:
    return {"status": status, "detail": detail, "checked_at": _now().isoformat()}


def _intel_component(db: Session) -> dict[str, Any]:
    sources: dict[str, Any] = {}
    worst = "HEALTHY"
    for source, window in FRESHNESS_WINDOWS.items():
        last: datetime | None
        if source == "EPSS":
            last = db.execute(select(func.max(VulnerabilityEpss.updated_at))).scalar_one()
        else:
            last = db.execute(
                select(func.max(VulnerabilitySyncHistory.finished_at)).where(
                    VulnerabilitySyncHistory.source == source,
                    VulnerabilitySyncHistory.status.in_(["SUCCESS", "PARTIAL"]),
                )
            ).scalar_one()
        if last is None:
            status = "UNKNOWN"
        else:
            age = _now() - last
            status = "HEALTHY" if age <= window else "DEGRADED"
        sources[source] = {
            "status": status,
            "last_success_at": last.isoformat() if last else None,
            "window_hours": int(window.total_seconds() // 3600),
        }
        if _STATUS_RANK.get(status, 2) > _STATUS_RANK.get(worst, 1):
            worst = status
    return _component(worst, sources=sources)


def _repository_component(db: Session) -> dict[str, Any]:
    settings = get_settings()
    repos = list(
        db.execute(select(Asset).where(Asset.kind == "REPOSITORY")).scalars()
    )
    now = _now()
    never = 0
    stale = 0
    failing = 0
    for asset in repos:
        if asset.last_scan_at is None:
            never += 1
            continue
        interval = asset.scan_interval_minutes or settings.scanner_schedule_interval_minutes
        if now - asset.last_scan_at > timedelta(minutes=interval * 2):
            stale += 1
        if asset.last_scan_status == ScanStatus.FAILED.value:
            failing += 1
    if not repos:
        return _component("UNKNOWN", reason="no_repositories", repositories=0)
    status = "HEALTHY"
    if failing or stale:
        status = "DEGRADED"
    return _component(
        status,
        repositories=len(repos),
        never_scanned=never,
        stale=stale,
        last_scan_failed=failing,
    )


def _sbom_component(db: Session) -> dict[str, Any]:
    settings = get_settings()
    last_run = db.execute(
        select(func.max(SbomMonitoringRun.started_at))
    ).scalar_one()
    if last_run is None:
        return _component("UNKNOWN", reason="no_sbom_monitoring_runs")
    age = _now() - last_run
    window = timedelta(minutes=max(120, settings.sbom_dependency_check_interval_minutes * 2))
    failed = int(
        db.execute(
            select(func.count(SbomMonitoringRun.id)).where(
                SbomMonitoringRun.status == "FAILED",
                SbomMonitoringRun.started_at >= _now() - timedelta(days=1),
            )
        ).scalar_one()
    )
    return _component(
        "DEGRADED" if age > window or failed else "HEALTHY",
        last_run_at=last_run.isoformat(),
        window_minutes=int(window.total_seconds() // 60),
        failed_last_24h=failed,
    )


def _events_component(db: Session) -> dict[str, Any]:
    settings = get_settings()
    last = db.execute(select(func.max(SecurityEvent.last_seen_at))).scalar_one()
    rules = int(
        db.execute(
            select(func.count(DetectionRule.id)).where(DetectionRule.enabled.is_(True))
        ).scalar_one()
    )
    if not settings.events_ingest_token:
        return _component(
            "DISABLED",
            reason="ANS_EVENTS_INGEST_TOKEN is not set",
            enabled_rules=rules,
            last_event_at=last.isoformat() if last else None,
        )
    if last is None:
        return _component("UNKNOWN", reason="no_events_received", enabled_rules=rules)
    lag_minutes = int((_now() - last).total_seconds() // 60)
    return _component(
        "HEALTHY" if lag_minutes <= 60 else "DEGRADED",
        last_event_at=last.isoformat(),
        lag_minutes=lag_minutes,
        enabled_rules=rules,
    )


def _queue_component(db: Session) -> dict[str, Any]:
    from app.workers.models import Job

    counts = {
        status: int(count)
        for status, count in db.execute(
            select(Job.status, func.count(Job.id)).group_by(Job.status)
        ).all()
    }
    failed_24h = int(
        db.execute(
            select(func.count(Job.id)).where(
                Job.status == JobStatus.FAILED.value,
                Job.updated_at >= _now() - timedelta(days=1),
            )
        ).scalar_one()
    )
    queued = counts.get(JobStatus.QUEUED.value, 0)
    status = "HEALTHY"
    if failed_24h > 0 or queued > 500:
        status = "DEGRADED"
    return _component(status, by_status=counts, failed_last_24h=failed_24h)


def _infra_component(db: Session) -> dict[str, Any]:
    settings = get_settings()
    if not settings.infrastructure_enabled:
        return _component("DISABLED", reason="ANS_INFRASTRUCTURE_ENABLED=false")
    last = db.execute(select(func.max(InfrastructureScan.finished_at))).scalar_one()
    failed = int(
        db.execute(
            select(func.count(InfrastructureScan.id)).where(
                InfrastructureScan.status == "FAILED",
                InfrastructureScan.finished_at >= _now() - timedelta(days=1),
            )
        ).scalar_one()
    )
    if last is None:
        return _component("UNKNOWN", reason="no_infrastructure_scans", failed_last_24h=failed)
    return _component(
        "DEGRADED" if failed else "HEALTHY",
        last_scan_at=last.isoformat(),
        failed_last_24h=failed,
    )


def health(db: Session) -> dict[str, Any]:
    try:
        db.execute(text("SELECT 1"))
        database = _component("HEALTHY")
    except Exception as exc:  # pragma: no cover - infrastructure failure
        database = _component("DEGRADED", error=str(exc)[:200])

    components = {
        "database": database,
        "repository_monitoring": _repository_component(db),
        "sbom_monitoring": _sbom_component(db),
        "threat_intelligence": _intel_component(db),
        "event_ingestion": _events_component(db),
        "job_queue": _queue_component(db),
        "infrastructure": _infra_component(db),
        "ai": _component(
            "HEALTHY" if provider_status()["configured"] and provider_status()["enabled"]
            else "DISABLED",
            enabled=provider_status()["enabled"],
            configured=provider_status()["configured"],
            model=provider_status()["model"],
        ),
    }
    active = [component["status"] for component in components.values()]
    measured = [status for status in active if status != "DISABLED"]
    worst = max(measured, key=lambda status: _STATUS_RANK[status], default="UNKNOWN")
    return {"status": worst, "components": components, "checked_at": _now().isoformat()}


def overview(db: Session) -> dict[str, Any]:
    assets_by_kind = {
        kind: int(count)
        for kind, count in db.execute(
            select(Asset.kind, func.count(Asset.id)).group_by(Asset.kind)
        ).all()
    }
    findings_by_severity = {
        severity: int(
            db.execute(
                select(func.count(Finding.id)).where(
                    Finding.status.in_(ACTIVE_FINDING_STATUSES), Finding.severity == severity
                )
            ).scalar_one()
        )
        for severity in (Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value,
                         Severity.LOW.value, Severity.INFO.value, Severity.UNKNOWN.value)
    }
    incidents_active = int(
        db.execute(
            select(func.count(Incident.id)).where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES))
        ).scalar_one()
    )
    events_24h = int(
        db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.last_seen_at >= _now() - timedelta(hours=24)
            )
        ).scalar_one()
    )
    highest_events = list(
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.status == "OPEN")
            .order_by(SecurityEvent.risk_score.desc().nullslast(), SecurityEvent.last_seen_at.desc())
            .limit(5)
        ).scalars()
    )
    top_incidents = list(
        db.execute(
            select(Incident)
            .where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES))
            .order_by(Incident.risk_score.desc())
            .limit(5)
        ).scalars()
    )
    # ORM rows are converted here so the endpoint contract is stable and the
    # response can never leak un-serializable objects.
    from app.modules.events.schemas import EventRead
    from app.modules.incidents.schemas import IncidentRead

    return {
        "assets": {
            "total": sum(assets_by_kind.values()),
            "by_kind": assets_by_kind,
        },
        "findings": {
            "by_severity": findings_by_severity,
            "active": sum(findings_by_severity.values()),
        },
        "incidents": {
            "active": incidents_active,
            "top": [IncidentRead.model_validate(item) for item in top_incidents],
        },
        "events": {
            "last_24h": events_24h,
            "highest_risk": [EventRead.model_validate(item) for item in highest_events],
        },
        "health": health(db)["status"],
    }
