"""API schemas for security events and detection rules."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    category: str
    source: str
    source_event_id: str | None
    event_type: str
    title: str
    description: str | None
    severity: str
    status: str
    asset_id: uuid.UUID | None
    incident_id: uuid.UUID | None
    rule_slug: str | None
    rule_version: int | None
    risk_score: int | None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    acknowledged_at: datetime | None
    closed_at: datetime | None
    normalized: dict[str, Any] = Field(default_factory=dict)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class EventDetail(EventRead):
    #: Bounded and redacted at ingestion; only exposed on the detail endpoint.
    raw: dict[str, Any] = Field(default_factory=dict)


class EventNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class EventNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    author: str
    body: str
    created_at: datetime


class RuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    description: str | None
    category: str
    severity: str
    rule_type: str
    source: str
    enabled: bool
    version: int
    conditions: dict[str, Any]
    threshold: dict[str, Any] | None
    create_incident: bool
    incident_priority: str | None
    match_count: int
    last_matched_at: datetime | None
    created_at: datetime
    updated_at: datetime


class RuleCreate(BaseModel):
    slug: str = Field(min_length=3, max_length=120, pattern="^[a-z0-9][a-z0-9_.-]+$")
    name: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    category: str = Field(default="RUNTIME", max_length=24)
    severity: str = Field(default="MEDIUM", max_length=16)
    rule_type: str = Field(default="SIGNATURE", max_length=16)
    conditions: dict[str, Any]
    threshold: dict[str, Any] | None = None
    create_incident: bool = False
    incident_priority: str | None = Field(default=None, max_length=4)
    enabled: bool = True


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    severity: str | None = Field(default=None, max_length=16)
    enabled: bool | None = None
    conditions: dict[str, Any] | None = None
    threshold: dict[str, Any] | None = None
    create_incident: bool | None = None
    incident_priority: str | None = Field(default=None, max_length=4)


class EventSummary(BaseModel):
    window_hours: int
    total: int
    open: int
    by_category: dict[str, int]
    by_severity: dict[str, int]
    last_event_at: datetime | None
    per_hour: list[dict[str, Any]]
