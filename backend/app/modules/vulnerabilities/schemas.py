"""Schemas for the vulnerability intelligence API."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict


class VulnerabilityReferenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    ref_type: str | None
    source: str | None


class AffectedPackageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ecosystem: str
    package_name: str
    purl: str | None
    affected_versions: list[str]
    fixed_versions: list[str]


class VulnerabilityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    source_id: str
    cve_id: str | None
    osv_id: str | None
    summary: str | None
    severity: str
    cvss_score: float | None
    is_kev: bool
    published_at: datetime | None
    modified_at: datetime | None


class VulnerabilityDetail(VulnerabilityRead):
    description: str | None
    cvss_vector: str | None
    kev_due_date: date | None
    kev_required_action: str | None
    references: list[VulnerabilityReferenceRead] = []
    affected_packages: list[AffectedPackageRead] = []


class SyncHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    duration_seconds: int | None
    records_processed: int
    records_created: int
    records_updated: int
    error_message: str | None


class SyncTriggerResponse(BaseModel):
    job_id: uuid.UUID
    source: str
    status: str


class IntelligenceStats(BaseModel):
    total: int
    kev: int
    by_source: dict[str, int]
    by_severity: dict[str, int]
    last_sync: dict[str, str | None]
