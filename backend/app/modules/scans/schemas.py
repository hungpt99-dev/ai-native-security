"""Schemas for scans and scanner executions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ScannerExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scanner: str
    status: str
    version: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: int | None
    exit_code: int | None
    result_count: int
    command: dict[str, Any] | None
    stdout_excerpt: str | None
    stderr_excerpt: str | None
    error_message: str | None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    trigger: str
    branch: str | None
    commit_sha: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: int | None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    unknown_count: int
    new_findings: int
    resolved_findings: int
    error_message: str | None
    created_at: datetime


class ScanDetail(ScanRead):
    asset_name: str | None = None
    asset_repo_url: str | None = None
    executions: list[ScannerExecutionRead] = []


class ScanCreateResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    asset_id: uuid.UUID
