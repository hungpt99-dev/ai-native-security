"""Incident lifecycle.

Events are attached by the ingestion path, findings by deterministic
correlation, and humans move the status. The service is the only writer of
``incidents.status`` — no AI service imports it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    ACTIVE_INCIDENT_STATUSES,
    ALLOWED_INCIDENT_TRANSITIONS,
    IncidentEventKind,
    IncidentPriority,
    IncidentStatus,
    Severity,
)
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.modules.assets.models import Asset
from app.modules.events.models import SecurityEvent
from app.modules.findings.models import Finding
from app.modules.incidents import risk as risk_engine
from app.modules.incidents.models import (
    Incident,
    IncidentFinding,
    IncidentTimelineEntry,
)
from app.modules.security_intelligence.models import AssetSecurityProfile

logger = get_logger(__name__)

_SEVERITY_RANK = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
    Severity.UNKNOWN.value: 5,
}


def _now() -> datetime:
    return datetime.now(UTC)


def get_incident_or_404(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise NotFoundError("Incident not found", details={"incident_id": str(incident_id)})
    return incident


def list_incidents(
    db: Session,
    params: PageParams,
    *,
    statuses: list[str] | None = None,
    severities: list[str] | None = None,
    priorities: list[str] | None = None,
    asset_id: uuid.UUID | None = None,
    asset_scope: frozenset[uuid.UUID] | None = None,
    category: str | None = None,
    search: str | None = None,
    active_only: bool = False,
    sort_by: str = "opened_at",
    sort_order: str = "desc",
) -> tuple[list[Incident], int]:
    stmt = select(Incident)
    if asset_scope is not None:
        stmt = stmt.where(Incident.asset_id.in_(list(asset_scope)))
    if active_only:
        stmt = stmt.where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES))
    if statuses:
        stmt = stmt.where(Incident.status.in_(statuses))
    if severities:
        stmt = stmt.where(Incident.severity.in_(severities))
    if priorities:
        stmt = stmt.where(Incident.priority.in_(priorities))
    if asset_id:
        stmt = stmt.where(Incident.asset_id == asset_id)
    if category:
        stmt = stmt.where(Incident.category == category)
    if search:
        like = f"%{search.strip()[:200]}%"
        stmt = stmt.where(or_(Incident.title.ilike(like), Incident.summary.ilike(like)))

    columns = {
        "opened_at": Incident.opened_at,
        "updated_at": Incident.updated_at,
        "severity": Incident.severity,
        "risk_score": Incident.risk_score,
        "priority": Incident.priority,
    }
    column = columns.get(sort_by, Incident.opened_at)
    stmt = stmt.order_by(column.asc() if sort_order.lower() == "asc" else column.desc())
    return paginate(db, stmt, params)


def timeline(db: Session, incident_id: uuid.UUID) -> list[IncidentTimelineEntry]:
    return list(
        db.execute(
            select(IncidentTimelineEntry)
            .where(IncidentTimelineEntry.incident_id == incident_id)
            .order_by(IncidentTimelineEntry.created_at.asc(), IncidentTimelineEntry.id)
        ).scalars()
    )


def add_timeline(
    db: Session,
    incident: Incident,
    *,
    kind: str,
    message: str,
    actor: str = "system",
    detail: dict[str, Any] | None = None,
) -> IncidentTimelineEntry:
    entry = IncidentTimelineEntry(
        incident_id=incident.id,
        kind=kind,
        message=message[:4000],
        actor=actor[:120],
        detail=detail or {},
    )
    db.add(entry)
    db.flush()
    return entry


def _asset_risk_context(db: Session, asset_id: uuid.UUID | None) -> tuple[str | None, bool | None]:
    if asset_id is None:
        return None, None
    profile = db.get(AssetSecurityProfile, asset_id)
    if profile is None:
        return None, None
    return profile.criticality, profile.internet_exposed


def recompute_risk(db: Session, incident: Incident) -> None:
    criticality, exposed = _asset_risk_context(db, incident.asset_id)
    matched = bool((incident.metadata_json or {}).get("threat_matched"))
    result = risk_engine.score(
        severity=incident.severity,
        criticality=criticality,
        internet_exposed=exposed,
        threat_matched=matched,
        event_count=incident.event_count,
        rule_priority=(incident.metadata_json or {}).get("rule_priority"),
    )
    incident.risk_score = result.score
    incident.priority = result.priority
    incident.metadata_json = {
        **(incident.metadata_json or {}),
        "risk": result.as_dict(),
    }


def _correlation_key(rule_slug: str | None, event: Any) -> str:
    asset_key = str(getattr(event, "asset_id", None) or "")
    if not asset_key:
        normalized = getattr(event, "normalized", {}) or {}
        container = (normalized.get("container") or {}).get("image") or ""
        asset_key = container or normalized.get("host") or "global"
    return f"{rule_slug or 'runtime'}:{asset_key}"[:250]


def create_or_attach_from_event(
    db: Session,
    event: SecurityEvent,
    *,
    rule_slug: str | None,
    rule_priority: str | None,
    actor: str = "detection",
) -> Incident:
    """Create an incident for a matching event, or attach to the open one.

    Reuse is scoped by ``correlation_key`` and a bounded window, so a recurring
    detection appends evidence instead of opening an incident per log line.
    """
    settings = get_settings()
    now = _now()
    window = timedelta(hours=max(1, settings.incident_reuse_window_hours))
    key = _correlation_key(rule_slug, event)

    existing = db.execute(
        select(Incident)
        .where(
            Incident.correlation_key == key,
            Incident.status.in_(ACTIVE_INCIDENT_STATUSES),
            Incident.opened_at >= now - window,
        )
        .order_by(Incident.opened_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    criticality, exposed = _asset_risk_context(db, event.asset_id)
    threat_matched = bool((event.enrichment or {}).get("threat_matches"))

    if existing is not None:
        existing.severity = risk_engine.worst_severity([existing.severity, event.severity])
        existing.event_count = int(existing.event_count or 0) + 1
        existing.acknowledged_at = existing.acknowledged_at
        existing.metadata_json = {
            **(existing.metadata_json or {}),
            "threat_matched": bool((existing.metadata_json or {}).get("threat_matched"))
            or threat_matched,
        }
        result = risk_engine.score(
            severity=existing.severity,
            criticality=criticality,
            internet_exposed=exposed,
            threat_matched=bool(existing.metadata_json.get("threat_matched")),
            event_count=existing.event_count,
            rule_priority=(existing.metadata_json or {}).get("rule_priority"),
        )
        existing.risk_score = result.score
        existing.priority = result.priority
        existing.metadata_json = {**existing.metadata_json, "risk": result.as_dict()}
        event.incident_id = existing.id
        add_timeline(
            db,
            existing,
            kind=IncidentEventKind.EVENT_ATTACHED.value,
            message=f"Event attached: {event.title}",
            actor=actor,
            detail={
                "event_id": str(event.id),
                "severity": event.severity,
                "occurrence_count": event.occurrence_count,
            },
        )
        return existing

    incident = Incident(
        title=(event.title or "Security event")[:300],
        summary=event.description,
        severity=event.severity,
        priority=IncidentPriority.P3.value,
        status=IncidentStatus.OPEN.value,
        category=event.category,
        asset_id=event.asset_id,
        correlation_key=key,
        detection_rule_slug=rule_slug,
        opened_at=now,
        event_count=1,
        metadata_json={
            "rule_priority": rule_priority,
            "threat_matched": threat_matched,
            "first_event_id": str(event.id),
        },
    )
    result = risk_engine.score(
        severity=event.severity,
        criticality=criticality,
        internet_exposed=exposed,
        threat_matched=threat_matched,
        event_count=1,
        rule_priority=rule_priority,
    )
    incident.risk_score = result.score
    incident.priority = result.priority
    incident.metadata_json = {**incident.metadata_json, "risk": result.as_dict()}
    db.add(incident)
    db.flush()

    event.incident_id = incident.id
    add_timeline(
        db,
        incident,
        kind=IncidentEventKind.CREATED.value,
        message=f"Incident opened by detection rule '{rule_slug or 'runtime'}'",
        actor=actor,
        detail={"event_id": str(event.id), "risk": result.as_dict()},
    )
    _link_same_asset_findings(db, incident, actor=actor)
    logger.info(
        "incident opened from event",
        extra={"extra_fields": {"incident_id": str(incident.id), "rule": rule_slug}},
    )
    return incident


def _link_same_asset_findings(db: Session, incident: Incident, *, actor: str) -> int:
    """Link active high/critical findings on the same asset.

    Deterministic: same asset, active status, at least HIGH. The cap prevents one
    incident from absorbing an entire backlog.
    """
    if incident.asset_id is None:
        return 0
    rows = db.execute(
        select(Finding)
        .where(
            Finding.asset_id == incident.asset_id,
            Finding.status.in_(ACTIVE_FINDING_STATUSES),
            Finding.severity.in_([Severity.CRITICAL.value, Severity.HIGH.value]),
        )
        .order_by(Finding.severity, Finding.last_detected_at.desc())
        .limit(10)
    ).scalars()
    linked = 0
    for finding in rows:
        exists = db.execute(
            select(IncidentFinding.id).where(
                IncidentFinding.incident_id == incident.id,
                IncidentFinding.finding_id == finding.id,
            )
        ).scalar_one_or_none()
        if exists:
            continue
        db.add(
            IncidentFinding(
                incident_id=incident.id,
                finding_id=finding.id,
                reason="same_asset_high_severity",
            )
        )
        linked += 1
    if linked:
        incident.finding_count = int(incident.finding_count or 0) + linked
        add_timeline(
            db,
            incident,
            kind=IncidentEventKind.FINDING_ATTACHED.value,
            message=f"{linked} active high/critical finding(s) on the same asset linked",
            actor=actor,
            detail={"reason": "same_asset_high_severity", "count": linked},
        )
        db.flush()
    return linked


def details(db: Session, incident_id: uuid.UUID, *, event_limit: int = 100) -> dict[str, Any]:
    incident = get_incident_or_404(db, incident_id)
    events = list(
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.incident_id == incident.id)
            .order_by(SecurityEvent.last_seen_at.desc())
            .limit(max(1, min(event_limit, 500)))
        ).scalars()
    )
    links = list(
        db.execute(
            select(IncidentFinding).where(IncidentFinding.incident_id == incident.id)
        ).scalars()
    )
    findings = (
        list(
            db.execute(
                select(Finding).where(Finding.id.in_([link.finding_id for link in links]))
            ).scalars()
        )
        if links
        else []
    )
    asset = db.get(Asset, incident.asset_id) if incident.asset_id else None
    return {
        "incident": incident,
        "asset": asset,
        "events": events,
        "findings": findings,
        "timeline": timeline(db, incident.id),
    }


def change_status(
    db: Session,
    incident: Incident,
    *,
    new_status: str,
    actor: str,
    note: str | None = None,
) -> Incident:
    if new_status not in {item.value for item in IncidentStatus}:
        raise ValidationError("Unknown incident status")
    if new_status == incident.status:
        raise ConflictError("Incident already has that status")
    allowed = ALLOWED_INCIDENT_TRANSITIONS.get(incident.status, set())
    if new_status not in allowed:
        raise ConflictError(
            "Status transition is not allowed",
            details={"from": incident.status, "to": new_status, "allowed": sorted(allowed)},
        )
    previous = incident.status
    incident.status = new_status
    now = _now()
    if new_status == IncidentStatus.INVESTIGATING.value and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    if new_status == IncidentStatus.CONTAINED.value:
        incident.contained_at = now
    if new_status == IncidentStatus.RESOLVED.value:
        incident.resolved_at = now
    if new_status == IncidentStatus.CLOSED.value:
        incident.closed_at = now
    add_timeline(
        db,
        incident,
        kind=IncidentEventKind.STATUS_CHANGED.value,
        message=(note or f"Status changed from {previous} to {new_status}")[:4000],
        actor=actor,
        detail={"from": previous, "to": new_status},
    )
    db.flush()
    return incident


def assign(db: Session, incident: Incident, *, assignee: str | None, actor: str) -> Incident:
    previous = incident.assigned_to
    incident.assigned_to = (assignee or None) and assignee[:120]
    add_timeline(
        db,
        incident,
        kind=IncidentEventKind.ASSIGNED.value,
        message=f"Assigned to {incident.assigned_to or 'nobody'} (was {previous or 'nobody'})",
        actor=actor,
        detail={"from": previous, "to": incident.assigned_to},
    )
    db.flush()
    return incident


def add_note(db: Session, incident: Incident, *, body: str, actor: str) -> IncidentTimelineEntry:
    if not body.strip():
        raise ValidationError("Note body cannot be empty")
    return add_timeline(
        db,
        incident,
        kind=IncidentEventKind.NOTE.value,
        message=body,
        actor=actor,
    )


def correlate(db: Session, incident: Incident, *, actor: str) -> dict[str, int]:
    """Attach deterministically related events and findings.

    Two rules only:
    * events on the same asset, same category, within ±24h of the incident and
      not already attached (bounded);
    * findings sharing a CVE with an already-linked finding, across assets — the
      supply-chain blast radius of the same defect.
    """
    now = _now()
    window = timedelta(hours=24)
    attached_events = 0
    if incident.asset_id is not None:
        candidates = list(
            db.execute(
                select(SecurityEvent)
                .where(
                    SecurityEvent.asset_id == incident.asset_id,
                    SecurityEvent.incident_id.is_(None),
                    SecurityEvent.last_seen_at >= incident.opened_at - window,
                    SecurityEvent.last_seen_at <= now + window,
                )
                .order_by(SecurityEvent.last_seen_at.desc())
                .limit(50)
            ).scalars()
        )
        for candidate in candidates:
            candidate.incident_id = incident.id
            attached_events += 1
    if attached_events:
        incident.event_count = int(incident.event_count or 0) + attached_events
        add_timeline(
            db,
            incident,
            kind=IncidentEventKind.CORRELATION.value,
            message=f"{attached_events} related event(s) attached by asset and time window",
            actor=actor,
            detail={"events": attached_events, "window_hours": 24},
        )

    linked_findings = 0
    linked_ids = {
        row.finding_id
        for row in db.execute(
            select(IncidentFinding).where(IncidentFinding.incident_id == incident.id)
        ).scalars()
    }
    cves: set[str] = set()
    if linked_ids:
        cves = {
            cve
            for (cve,) in db.execute(
                select(Finding.cve_id).where(
                    Finding.id.in_(linked_ids), Finding.cve_id.is_not(None)
                )
            )
            if cve
        }
    if cves:
        rows = db.execute(
            select(Finding).where(
                Finding.cve_id.in_(cves),
                Finding.id.not_in(linked_ids),
                Finding.status.in_(ACTIVE_FINDING_STATUSES),
            ).limit(25)
        ).scalars()
        for finding in rows:
            db.add(
                IncidentFinding(
                    incident_id=incident.id,
                    finding_id=finding.id,
                    reason="same_cve_across_assets",
                )
            )
            linked_findings += 1
    if linked_findings:
        incident.finding_count = int(incident.finding_count or 0) + linked_findings
        add_timeline(
            db,
            incident,
            kind=IncidentEventKind.FINDING_ATTACHED.value,
            message=f"{linked_findings} finding(s) sharing a CVE linked",
            actor=actor,
            detail={"reason": "same_cve_across_assets", "count": linked_findings},
        )
    incident.metadata_json = {
        **(incident.metadata_json or {}),
        "last_correlation_at": now.isoformat(),
    }
    recompute_risk(db, incident)
    db.flush()
    return {"events": attached_events, "findings": linked_findings}


def summary_counts(db: Session) -> dict[str, Any]:
    rows = db.execute(
        select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    ).all()
    by_status = {status: int(count) for status, count in rows}
    active = sum(by_status.get(status, 0) for status in ACTIVE_INCIDENT_STATUSES)
    opening = list(
        db.execute(
            select(Incident)
            .where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES))
            .order_by(Incident.risk_score.desc(), Incident.opened_at.desc())
            .limit(5)
        ).scalars()
    )
    return {
        "active": active,
        "by_status": by_status,
        "by_severity": {
            severity: int(
                db.execute(
                    select(func.count(Incident.id)).where(
                        Incident.status.in_(ACTIVE_INCIDENT_STATUSES),
                        Incident.severity == severity,
                    )
                ).scalar_one()
            )
            for severity in _SEVERITY_RANK
        },
        "top_open": opening,
    }
