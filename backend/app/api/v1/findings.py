"""Findings API: filtering, pagination, detail and status transitions."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.assets.models import Asset
from app.modules.findings import service
from app.modules.findings.schemas import (
    FindingDetail,
    FindingHistoryRead,
    FindingRead,
    FindingStatusUpdate,
)

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=Page[FindingRead])
def list_findings(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    scan_id: Annotated[uuid.UUID | None, Query()] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    scanner: Annotated[list[str] | None, Query()] = None,
    status: Annotated[list[str] | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    cve_id: Annotated[str | None, Query(max_length=32)] = None,
    sort_by: Annotated[str, Query()] = "severity",
    sort_order: Annotated[str, Query(pattern="^(?i)(asc|desc)$")] = "asc",
) -> Page[FindingRead]:
    rows, total = service.list_findings(
        db,
        params,
        asset_id=asset_id,
        scan_id=scan_id,
        scanners=scanner,
        severities=severity,
        statuses=status,
        search=search,
        cve_id=cve_id,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return Page.build([FindingRead.model_validate(row) for row in rows], total, params)


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> FindingDetail:
    finding = service.get_finding_or_404(db, finding_id)
    asset = db.get(Asset, finding.asset_id)
    detail = FindingDetail.model_validate(finding)
    detail.asset_name = asset.name if asset else None
    detail.asset_repo_url = asset.repo_url if asset else None
    detail.history = [
        FindingHistoryRead.model_validate(entry)
        for entry in service.history_for_finding(db, finding.id)
    ]
    return detail


@router.patch("/{finding_id}/status", response_model=FindingDetail)
def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> FindingDetail:
    finding = service.get_finding_or_404(db, finding_id)
    finding = service.update_status(
        db,
        finding,
        payload.status,
        actor=principal.subject,
        note=payload.note,
    )
    db.commit()
    db.refresh(finding)
    asset = db.get(Asset, finding.asset_id)
    detail = FindingDetail.model_validate(finding)
    detail.asset_name = asset.name if asset else None
    detail.asset_repo_url = asset.repo_url if asset else None
    detail.history = [
        FindingHistoryRead.model_validate(entry)
        for entry in service.history_for_finding(db, finding.id)
    ]
    return detail
