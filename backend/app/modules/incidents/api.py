"""Incident API: triage, timeline, correlation, AI investigation."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal, Principal
from app.core.enums import INCIDENT_PRIORITIES, INCIDENT_STATUSES, EventCategory, Severity
from app.core.errors import NotFoundError, ValidationError
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.ai.services import incident_investigation
from app.modules.audit import service as audit
from app.modules.events.schemas import EventRead
from app.modules.incidents import service
from app.modules.incidents.schemas import (
    AssetSummary,
    CorrelateResponse,
    IncidentAssign,
    IncidentDetail,
    IncidentNoteCreate,
    IncidentRead,
    IncidentStatusUpdate,
    IncidentSummary,
    LinkedFindingRead,
    TimelineEntryRead,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])

_SEVERITIES = {item.value for item in Severity}


def _visible(principal: Principal, incident) -> None:  # type: ignore[no-untyped-def]
    if not principal.allows(incident.asset_id):
        raise NotFoundError("Incident not found")


@router.get("", response_model=Page[IncidentRead])
def list_incidents(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    params: Annotated[PageParams, Depends(page_params)],
    status_filter: Annotated[list[str] | None, Query(alias="status")] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    priority: Annotated[list[str] | None, Query()] = None,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    active_only: Annotated[bool, Query()] = False,
    sort_by: Annotated[str, Query()] = "opened_at",
    sort_order: Annotated[str, Query(pattern="^(?i)(asc|desc)$")] = "desc",
) -> Page[IncidentRead]:
    for value in (status_filter or []):
        if value not in INCIDENT_STATUSES:
            raise ValidationError("Unknown incident status", details={"value": value})
    for value in (severity or []):
        if value not in _SEVERITIES:
            raise ValidationError("Unknown severity", details={"value": value})
    for value in (priority or []):
        if value not in INCIDENT_PRIORITIES:
            raise ValidationError("Unknown priority", details={"value": value})
    if category and category not in {item.value for item in EventCategory}:
        raise ValidationError("Unknown category")
    if asset_id is not None and not principal.allows(asset_id):
        return Page.build([], 0, params)

    incidents, total = service.list_incidents(
        db,
        params,
        statuses=status_filter,
        severities=severity,
        priorities=priority,
        asset_id=asset_id,
        asset_scope=principal.asset_scope,
        category=category,
        search=search,
        active_only=active_only,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return Page.build([IncidentRead.model_validate(item) for item in incidents], total, params)


@router.get("/summary", response_model=IncidentSummary)
def incident_summary(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> IncidentSummary:
    data = service.summary_counts(db)
    top = [
        item for item in data["top_open"] if principal.allows(item.asset_id)
    ]
    return IncidentSummary(
        active=data["active"],
        by_status=data["by_status"],
        by_severity=data["by_severity"],
        top_open=[IncidentRead.model_validate(item) for item in top],
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> IncidentDetail:
    data = service.details(db, incident_id)
    incident = data["incident"]
    _visible(principal, incident)
    events = [event for event in data["events"] if principal.allows(event.asset_id)]
    return IncidentDetail(
        incident=IncidentRead.model_validate(incident),
        asset=AssetSummary.model_validate(data["asset"]) if data["asset"] else None,
        events=[EventRead.model_validate(event) for event in events],
        findings=[LinkedFindingRead.model_validate(finding) for finding in data["findings"]],
        timeline=[TimelineEntryRead.model_validate(entry) for entry in data["timeline"]],
    )


@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentStatusUpdate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> IncidentRead:
    incident = service.get_incident_or_404(db, incident_id)
    _visible(principal, incident)
    service.change_status(
        db, incident, new_status=payload.status, actor=principal.subject, note=payload.note
    )
    audit.record(
        db,
        actor=principal.subject,
        action="UPDATE",
        resource_type="incidents",
        resource_id=incident.id,
        detail={"status": incident.status, "severity": incident.severity},
    )
    return IncidentRead.model_validate(incident)


@router.post("/{incident_id}/assign", response_model=IncidentRead)
def assign_incident(
    incident_id: uuid.UUID,
    payload: IncidentAssign,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> IncidentRead:
    incident = service.get_incident_or_404(db, incident_id)
    _visible(principal, incident)
    service.assign(db, incident, assignee=payload.assignee, actor=principal.subject)
    return IncidentRead.model_validate(incident)


@router.post("/{incident_id}/notes", response_model=TimelineEntryRead, status_code=status.HTTP_201_CREATED)
def add_note(
    incident_id: uuid.UUID,
    payload: IncidentNoteCreate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> TimelineEntryRead:
    incident = service.get_incident_or_404(db, incident_id)
    _visible(principal, incident)
    entry = service.add_note(db, incident, body=payload.body, actor=principal.subject)
    return TimelineEntryRead.model_validate(entry)


# -------------------------------------------------------------- investigation
@router.post("/{incident_id}/investigate")
def investigate_incident(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    """Run (or re-run) an AI investigation. It cannot change the incident."""
    incident = service.get_incident_or_404(db, incident_id)
    _visible(principal, incident)
    row = incident_investigation.investigate(db, incident.id, principal=principal.subject)
    audit.record(
        db,
        actor=principal.subject,
        action="EXECUTE",
        resource_type="incident_investigations",
        resource_id=row.id,
        detail={"incident_id": str(incident.id), "status": row.status},
    )
    return incident_investigation.to_dict(row)


@router.get("/{incident_id}/investigations")
def list_investigations(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> list[dict[str, Any]]:
    incident = service.get_incident_or_404(db, incident_id)
    _visible(principal, incident)
    return [
        incident_investigation.to_dict(row)
        for row in incident_investigation.history(db, incident.id)
    ]


@router.post("/{incident_id}/correlate", response_model=CorrelateResponse)
def correlate_incident(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> CorrelateResponse:
    incident = service.get_incident_or_404(db, incident_id)
    _visible(principal, incident)
    result = service.correlate(db, incident, actor=principal.subject)
    audit.record(
        db,
        actor=principal.subject,
        action="EXECUTE",
        resource_type="incidents",
        resource_id=incident.id,
        detail={"correlation": result},
    )
    return CorrelateResponse(**result)
