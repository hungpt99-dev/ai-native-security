"""Asset inventory HTTP API."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.enums import ScanTrigger
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.assets import service
from app.modules.assets.schemas import AssetCreate, AssetRead, AssetUpdate
from app.modules.scans.schemas import ScanCreateResponse, ScanRead
from app.modules.scans.service import create_scan, list_scans

router = APIRouter(prefix="/assets", tags=["assets"])


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> AssetRead:
    asset = service.create_asset(db, payload)
    db.commit()
    return AssetRead.from_asset(asset)


@router.get("", response_model=Page[AssetRead])
def list_assets(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    search: Annotated[str | None, Query(max_length=200)] = None,
    provider: Annotated[str | None, Query(pattern="^(?i)(github|gitlab)$")] = None,
    monitoring: Annotated[bool | None, Query()] = None,
    sort_by: Annotated[str, Query()] = "created_at",
    sort_order: Annotated[str, Query(pattern="^(?i)(asc|desc)$")] = "desc",
) -> Page[AssetRead]:
    assets, total = service.list_assets(
        db,
        params,
        search=search,
        provider=provider,
        monitoring_enabled=monitoring,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return Page.build([AssetRead.from_asset(a) for a in assets], total, params)


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> AssetRead:
    return AssetRead.from_asset(service.get_asset_or_404(db, asset_id))


@router.put("/{asset_id}", response_model=AssetRead)
def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> AssetRead:
    asset = service.get_asset_or_404(db, asset_id)
    asset = service.update_asset(db, asset, payload)
    db.commit()
    db.refresh(asset)
    return AssetRead.from_asset(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> None:
    asset = service.get_asset_or_404(db, asset_id)
    service.delete_asset(db, asset)
    db.commit()


@router.post("/{asset_id}/scan", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ScanCreateResponse:
    asset = service.get_asset_or_404(db, asset_id)
    scan = create_scan(
        db,
        asset,
        trigger=ScanTrigger.MANUAL,
        requested_by=principal.subject,
    )
    db.commit()
    return ScanCreateResponse(scan_id=scan.id, status=scan.status, asset_id=asset.id)


@router.get("/{asset_id}/scans", response_model=Page[ScanRead])
def list_asset_scans(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
) -> Page[ScanRead]:
    service.get_asset_or_404(db, asset_id)
    scans, total = list_scans(db, params, asset_id=asset_id)
    return Page.build([ScanRead.model_validate(s) for s in scans], total, params)
