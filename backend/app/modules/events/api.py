"""Security event API: query, triage, detection-rule authoring."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal, Principal
from app.core.enums import (
    EVENT_CATEGORIES,
    EVENT_SOURCES,
    EVENT_STATUSES,
    DetectionRuleSource,
    DetectionRuleType,
    Severity,
)
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.audit import service as audit
from app.modules.events import rules as rule_engine
from app.modules.events import service
from app.modules.events.models import DetectionRule
from app.modules.events.schemas import (
    EventDetail,
    EventNoteCreate,
    EventNoteRead,
    EventRead,
    EventSummary,
    RuleCreate,
    RuleRead,
    RuleUpdate,
)

router = APIRouter(prefix="/events", tags=["events"])

_SEVERITIES = {item.value for item in Severity}


def _scoped(principal: Principal, asset_id: uuid.UUID | None) -> None:
    if not principal.allows(asset_id):
        raise NotFoundError("Security event not found")


@router.get("", response_model=Page[EventRead])
def list_events(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    params: Annotated[PageParams, Depends(page_params)],
    category: Annotated[list[str] | None, Query()] = None,
    source: Annotated[list[str] | None, Query()] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    status: Annotated[list[str] | None, Query()] = None,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    incident_id: Annotated[uuid.UUID | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    since: Annotated[datetime | None, Query()] = None,
    sort_by: Annotated[str, Query()] = "last_seen_at",
    sort_order: Annotated[str, Query(pattern="^(?i)(asc|desc)$")] = "desc",
) -> Page[EventRead]:
    for value in (category or []) + (source or []) + (severity or []) + (status or []):
        if value not in EVENT_CATEGORIES + EVENT_SOURCES + EVENT_STATUSES + tuple(_SEVERITIES):
            raise ValidationError("Unknown filter value", details={"value": value})
    if asset_id is not None and not principal.allows(asset_id):
        return Page.build([], 0, params)
    events, total = service.list_events(
        db,
        params,
        categories=category,
        sources=source,
        severities=severity,
        statuses=status,
        asset_id=asset_id,
        incident_id=incident_id,
        asset_scope=principal.asset_scope,
        search=search,
        since=since,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return Page.build([EventRead.model_validate(event) for event in events], total, params)


@router.get("/summary", response_model=EventSummary)
def event_summary(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    window_hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> EventSummary:
    data = service.summary(db, window_hours=window_hours)
    return EventSummary(**data)


@router.get("/rules", response_model=list[RuleRead])
def list_rules(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> list[RuleRead]:
    return [
        RuleRead.model_validate(rule)
        for rule in db.execute(
            select(DetectionRule).order_by(DetectionRule.rule_type, DetectionRule.slug)
        ).scalars()
    ]


@router.post("/rules", response_model=RuleRead, status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: RuleCreate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> RuleRead:
    if payload.category not in EVENT_CATEGORIES:
        raise ValidationError("Unknown event category")
    if payload.severity not in _SEVERITIES:
        raise ValidationError("Unknown severity")
    if payload.rule_type not in {item.value for item in DetectionRuleType}:
        raise ValidationError("Unknown rule type")
    if payload.rule_type == "THRESHOLD":
        threshold = payload.threshold or {}
        if not isinstance(threshold.get("count"), int) or threshold["count"] < 2:
            raise ValidationError("Threshold rules need a count of at least 2")
    rule_engine.validate_conditions(payload.conditions)
    existing = db.execute(
        select(DetectionRule).where(DetectionRule.slug == payload.slug)
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("A rule with that slug already exists")

    rule = DetectionRule(
        slug=payload.slug,
        name=payload.name,
        description=payload.description,
        category=payload.category,
        severity=payload.severity,
        rule_type=payload.rule_type,
        source=DetectionRuleSource.CUSTOM.value,
        enabled=payload.enabled,
        conditions=payload.conditions,
        threshold=payload.threshold,
        create_incident=payload.create_incident,
        incident_priority=payload.incident_priority,
        created_by=principal.subject,
    )
    db.add(rule)
    db.flush()
    audit.record(
        db,
        actor=principal.subject,
        action="CREATE",
        resource_type="detection_rules",
        resource_id=rule.id,
        detail={"slug": rule.slug, "severity": rule.severity},
    )
    return RuleRead.model_validate(rule)


@router.patch("/rules/{rule_id}", response_model=RuleRead)
def update_rule(
    rule_id: uuid.UUID,
    payload: RuleUpdate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> RuleRead:
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise NotFoundError("Detection rule not found")
    data = payload.model_dump(exclude_unset=True)
    if "conditions" in data and data["conditions"] is not None:
        if rule.source == DetectionRuleSource.BUILTIN.value:
            raise ValidationError("Built-in rule conditions are immutable; clone it as a custom rule")
        rule_engine.validate_conditions(data["conditions"])
        rule.conditions = data["conditions"]
        rule.version = int(rule.version or 1) + 1
    if "severity" in data and data["severity"] is not None:
        if data["severity"] not in _SEVERITIES:
            raise ValidationError("Unknown severity")
        rule.severity = data["severity"]
    for field in ("name", "description", "enabled", "threshold", "create_incident", "incident_priority"):
        if field in data:
            setattr(rule, field, data[field])
    db.flush()
    audit.record(
        db,
        actor=principal.subject,
        action="UPDATE",
        resource_type="detection_rules",
        resource_id=rule.id,
        detail={"slug": rule.slug, "fields": sorted(data)},
    )
    return RuleRead.model_validate(rule)


@router.get("/{event_id}", response_model=EventDetail)
def get_event(
    event_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> EventDetail:
    event = service.get_event_or_404(db, event_id)
    _scoped(principal, event.asset_id)
    return EventDetail.model_validate(event)


@router.get("/{event_id}/notes", response_model=list[EventNoteRead])
def get_notes(
    event_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> list[EventNoteRead]:
    event = service.get_event_or_404(db, event_id)
    _scoped(principal, event.asset_id)
    return [EventNoteRead.model_validate(note) for note in service.notes(db, event.id)]


@router.post("/{event_id}/notes", response_model=EventNoteRead, status_code=status.HTTP_201_CREATED)
def add_note(
    event_id: uuid.UUID,
    payload: EventNoteCreate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> EventNoteRead:
    event = service.get_event_or_404(db, event_id)
    _scoped(principal, event.asset_id)
    note = service.add_note(db, event, body=payload.body, author=principal.subject)
    return EventNoteRead.model_validate(note)


@router.post("/{event_id}/acknowledge", response_model=EventRead)
def acknowledge_event(
    event_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> EventRead:
    event = service.get_event_or_404(db, event_id)
    _scoped(principal, event.asset_id)
    service.acknowledge(db, event, actor=principal.subject)
    return EventRead.model_validate(event)


@router.post("/{event_id}/close", response_model=EventRead)
def close_event(
    event_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    reason: Annotated[str | None, Query(max_length=4000)] = None,
) -> EventRead:
    event = service.get_event_or_404(db, event_id)
    _scoped(principal, event.asset_id)
    service.close(db, event, actor=principal.subject, reason=reason)
    return EventRead.model_validate(event)
