"""API schemas for incidents."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.modules.events.schemas import EventRead


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    title: str
    summary: str | None
    severity: str
    priority: str
    status: str
    category: str | None
    asset_id: uuid.UUID | None
    correlation_key: str
    detection_rule_slug: str | None
    risk_score: int
    event_count: int
    finding_count: int
    assigned_to: str | None
    opened_at: datetime
    acknowledged_at: datetime | None
    contained_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class TimelineEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    message: str
    actor: str
    detail: dict[str, Any]
    created_at: datetime


class LinkedFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    severity: str
    status: str
    cve_id: str | None
    package_name: str | None
    file_path: str | None
    asset_id: uuid.UUID


class AssetSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    repo_url: str | None
    external_ref: str | None


class IncidentDetail(BaseModel):
    incident: IncidentRead
    asset: AssetSummary | None
    events: list[EventRead]
    findings: list[LinkedFindingRead]
    timeline: list[TimelineEntryRead]


class IncidentStatusUpdate(BaseModel):
    status: str = Field(max_length=16)
    note: str | None = Field(default=None, max_length=4000)


class IncidentAssign(BaseModel):
    assignee: str | None = Field(default=None, max_length=120)


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class CorrelateResponse(BaseModel):
    events: int
    findings: int


class IncidentSummary(BaseModel):
    active: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    top_open: list[IncidentRead]
