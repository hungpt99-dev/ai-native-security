"""Infrastructure security API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.enums import (
    ASSET_KINDS,
    INFRA_SCAN_STATUSES,
    INFRA_SCANNERS,
    INFRA_TARGET_KINDS,
    AssetKind,
)
from app.core.errors import ConflictError, ValidationError
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.assets.models import Asset
from app.modules.audit import service as audit
from app.modules.infrastructure import service

router = APIRouter(prefix="/infrastructure", tags=["infrastructure"])

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


class ScanCreate(BaseModel):
    target_kind: str = Field(max_length=32)
    scanner: str = Field(max_length=32)
    asset_id: uuid.UUID | None = None
    target_ref: str | None = Field(default=None, max_length=500)


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    asset_id: uuid.UUID | None
    target_kind: str
    target_ref: str
    scanner: str
    status: str
    triggered_by: str
    requested_by: str | None
    commit_sha: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: int | None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    error_message: str | None
    scanner_version: str | None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class InfraAssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(max_length=32)
    external_ref: str = Field(min_length=3, max_length=500)
    parent_asset_id: uuid.UUID | None = None
    description: str | None = Field(default=None, max_length=4000)
    monitoring_enabled: bool = True
    infra_scan_interval_minutes: int | None = Field(default=None, ge=5, le=10080)


class InfraAssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    external_ref: str | None
    parent_asset_id: uuid.UUID | None
    repo_url: str | None
    description: str | None
    monitoring_enabled: bool
    last_infra_scan_at: datetime | None
    last_infra_scan_status: str | None
    created_at: datetime


@router.post("/scans", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ScanRead:
    row = service.create_scan(
        db,
        target_kind=payload.target_kind,
        scanner=payload.scanner,
        asset_id=payload.asset_id,
        target_ref=payload.target_ref,
        requested_by=principal.subject,
    )
    audit.record(
        db,
        actor=principal.subject,
        action="EXECUTE",
        resource_type="infrastructure_scans",
        resource_id=row.id,
        detail={"scanner": row.scanner, "target": row.target_ref},
    )
    return ScanRead.model_validate(row)


@router.get("/scans", response_model=Page[ScanRead])
def list_scans(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    params: Annotated[PageParams, Depends(page_params)],
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    status_filter: Annotated[list[str] | None, Query(alias="status")] = None,
    scanner: Annotated[str | None, Query()] = None,
    target_kind: Annotated[str | None, Query()] = None,
) -> Page[ScanRead]:
    if status_filter:
        for value in status_filter:
            if value not in INFRA_SCAN_STATUSES:
                raise ValidationError("Unknown infrastructure scan status")
    if scanner and scanner not in INFRA_SCANNERS:
        raise ValidationError("Unknown infrastructure scanner")
    if target_kind and target_kind not in INFRA_TARGET_KINDS:
        raise ValidationError("Unknown target kind")
    if asset_id is not None and not principal.allows(asset_id):
        return Page.build([], 0, params)
    rows, total = service.list_scans(
        db,
        params,
        asset_id=asset_id,
        statuses=status_filter,
        scanner=scanner,
        target_kind=target_kind,
    )
    if principal.asset_scope is not None:
        rows = [row for row in rows if principal.allows(row.asset_id)]
    return Page.build([ScanRead.model_validate(row) for row in rows], total, params)


@router.get("/scans/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ScanRead:
    row = service.get_scan_or_404(db, scan_id)
    if not principal.allows(row.asset_id):
        from app.core.errors import NotFoundError

        raise NotFoundError("Infrastructure scan not found")
    return ScanRead.model_validate(row)


@router.post("/scans/{scan_id}/retry", response_model=ScanRead)
def retry_scan(
    scan_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ScanRead:
    previous = service.get_scan_or_404(db, scan_id)
    if not principal.allows(previous.asset_id):
        from app.core.errors import NotFoundError

        raise NotFoundError("Infrastructure scan not found")
    row = service.create_scan(
        db,
        target_kind=previous.target_kind,
        scanner=previous.scanner,
        asset_id=previous.asset_id if previous.target_kind != "CONTAINER_IMAGE" else None,
        target_ref=previous.target_ref,
        requested_by=principal.subject,
        trigger="RETRY",
    )
    return ScanRead.model_validate(row)


@router.get("/summary")
def infrastructure_summary(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> dict[str, Any]:
    return service.summary(db)


@router.get("/scanners")
def infrastructure_scanners(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> list[dict[str, Any]]:
    return service.scanner_status(db)


@router.post("/assets", response_model=InfraAssetRead, status_code=status.HTTP_201_CREATED)
def create_infra_asset(
    payload: InfraAssetCreate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> InfraAssetRead:
    if payload.kind not in ASSET_KINDS or payload.kind == AssetKind.REPOSITORY.value:
        raise ValidationError("Infrastructure asset kind must be a non-repository kind")
    existing = db.execute(
        select(Asset).where(
            Asset.kind == payload.kind, Asset.external_ref == payload.external_ref.strip()
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(
            "An asset with that external reference already exists",
            details={"asset_id": str(existing.id)},
        )
    asset = Asset(
        name=payload.name,
        kind=payload.kind,
        repo_url=None,
        external_ref=payload.external_ref.strip(),
        parent_asset_id=payload.parent_asset_id,
        provider="NONE",
        default_branch="main",
        description=payload.description,
        monitoring_enabled=payload.monitoring_enabled,
        infra_scan_interval_minutes=payload.infra_scan_interval_minutes,
    )
    db.add(asset)
    db.flush()
    audit.record(
        db,
        actor=principal.subject,
        action="CREATE",
        resource_type="assets",
        resource_id=asset.id,
        detail={"kind": asset.kind, "external_ref": asset.external_ref},
    )
    return InfraAssetRead.model_validate(asset)


@router.get("/assets", response_model=Page[InfraAssetRead])
def list_infra_assets(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    params: Annotated[PageParams, Depends(page_params)],
    kind: Annotated[str | None, Query()] = None,
) -> Page[InfraAssetRead]:
    if kind and kind not in ASSET_KINDS:
        raise ValidationError("Unknown asset kind")
    stmt = select(Asset).where(Asset.kind != AssetKind.REPOSITORY.value)
    if kind:
        stmt = stmt.where(Asset.kind == kind)
    if principal.asset_scope is not None:
        stmt = stmt.where(Asset.id.in_(list(principal.asset_scope)))
    stmt = stmt.order_by(Asset.created_at.desc())
    from app.core.pagination import paginate

    rows, total = paginate(db, stmt, params)
    return Page.build([InfraAssetRead.model_validate(row) for row in rows], total, params)
