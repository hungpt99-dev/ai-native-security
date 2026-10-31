"""Scan history and scan detail API."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.assets.models import Asset
from app.modules.scans import service
from app.modules.scans.schemas import ScanDetail, ScanRead

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=Page[ScanRead])
def list_scans(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    trigger: Annotated[str | None, Query()] = None,
) -> Page[ScanRead]:
    scans, total = service.list_scans(
        db, params, asset_id=asset_id, status=status_filter, trigger=trigger
    )
    return Page.build([ScanRead.model_validate(s) for s in scans], total, params)


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ScanDetail:
    scan = service.get_scan_or_404(db, scan_id)
    executions = service.list_scanner_executions(db, scan.id)
    asset = db.get(Asset, scan.asset_id)
    detail = ScanDetail.model_validate(scan)
    detail.executions = list(executions)
    detail.asset_name = asset.name if asset else None
    detail.asset_repo_url = asset.repo_url if asset else None
    return detail


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(
    scan_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ScanRead:
    scan = service.get_scan_or_404(db, scan_id)
    scan = service.cancel_scan(db, scan)
    db.commit()
    return ScanRead.model_validate(scan)
