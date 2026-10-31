"""Pydantic schemas for findings and finding history."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    first_scan_id: uuid.UUID | None
    last_scan_id: uuid.UUID | None
    scanner: str
    rule_id: str
    title: str
    description: str | None
    category: str | None
    severity: str
    file_path: str | None
    line_number: int | None
    package_name: str | None
    package_version: str | None
    purl: str | None
    cve_id: str | None
    cvss_score: float | None
    status: str
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_json")
    first_detected_at: datetime
    last_detected_at: datetime
    resolved_at: datetime | None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class FindingHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event: str
    from_status: str | None
    to_status: str | None
    actor: str
    note: str | None
    scan_id: uuid.UUID | None
    created_at: datetime


class FindingDetail(FindingRead):
    asset_name: str | None = None
    asset_repo_url: str | None = None
    history: list[FindingHistoryRead] = []


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern="^(OPEN|CONFIRMED|FALSE_POSITIVE|ACCEPTED_RISK|RESOLVED)$")
    note: str | None = Field(default=None, max_length=2000)


class FindingsByScanner(BaseModel):
    scanner: str
    total: int


class SeverityCount(BaseModel):
    severity: str
    total: int
