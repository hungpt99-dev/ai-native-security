"""Pydantic schemas for the asset inventory API."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.validators import validate_branch_name


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    repo_url: str = Field(min_length=10, max_length=500)
    default_branch: str = Field(default="main", max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    access_token: str | None = Field(
        default=None,
        max_length=2048,
        description="Repository access token. Encrypted at rest, never returned.",
    )
    monitoring_enabled: bool = True
    scan_interval_minutes: int | None = Field(default=None, ge=5, le=10080)

    @field_validator("name", "default_branch")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()

    @field_validator("default_branch")
    @classmethod
    def _branch(cls, value: str) -> str:
        return validate_branch_name(value)


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    default_branch: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    monitoring_enabled: bool | None = None
    scan_interval_minutes: int | None = Field(default=None, ge=5, le=10080)
    access_token: str | None = Field(default=None, max_length=2048)
    clear_credential: bool = False

    @field_validator("default_branch")
    @classmethod
    def _branch(cls, value: str | None) -> str | None:
        return validate_branch_name(value) if value else value


class CredentialInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    label: str
    hint: str


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    repo_url: str
    provider: str
    default_branch: str
    description: str | None
    has_credential: bool = False
    credential_hint: str | None = None
    monitoring_enabled: bool
    scan_interval_minutes: int | None
    last_scan_at: datetime | None
    last_scan_status: str | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_asset(cls, asset) -> AssetRead:  # type: ignore[no-untyped-def]
        return cls(
            id=asset.id,
            name=asset.name,
            repo_url=asset.repo_url,
            provider=asset.provider,
            default_branch=asset.default_branch,
            description=asset.description,
            has_credential=asset.credential_id is not None,
            credential_hint=asset.credential.secret_hint if asset.credential else None,
            monitoring_enabled=asset.monitoring_enabled,
            scan_interval_minutes=asset.scan_interval_minutes,
            last_scan_at=asset.last_scan_at,
            last_scan_status=asset.last_scan_status,
            created_at=asset.created_at,
            updated_at=asset.updated_at,
        )
