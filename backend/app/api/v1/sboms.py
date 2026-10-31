"""SBOM API: history, metadata, packages and download."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.assets.service import get_asset_or_404
from app.modules.sbom import service

router = APIRouter(tags=["sbom"])


class SbomRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    scan_id: uuid.UUID | None
    format: str
    spec_version: str | None
    tool_name: str
    tool_version: str | None
    sha256: str
    size_bytes: int
    package_count: int
    created_at: datetime


class SbomPackageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: str
    ecosystem: str | None
    purl: str | None
    license: str | None
    source_type: str | None
    cpe: str | None


@router.get("/assets/{asset_id}/sboms", response_model=Page[SbomRead])
def list_asset_sboms(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
) -> Page[SbomRead]:
    get_asset_or_404(db, asset_id)
    rows, total = service.list_sboms(db, params, asset_id=asset_id)
    return Page.build([SbomRead.model_validate(row) for row in rows], total, params)


@router.get("/sboms", response_model=Page[SbomRead])
def list_sboms(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
) -> Page[SbomRead]:
    rows, total = service.list_sboms(db, params, asset_id=asset_id)
    return Page.build([SbomRead.model_validate(row) for row in rows], total, params)


@router.get("/sboms/{sbom_id}", response_model=SbomRead)
def get_sbom(
    sbom_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> SbomRead:
    return SbomRead.model_validate(service.get_sbom_or_404(db, sbom_id))


@router.get("/sboms/{sbom_id}/packages", response_model=Page[SbomPackageRead])
def list_sbom_packages(
    sbom_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    search: Annotated[str | None, Query(max_length=200)] = None,
    ecosystem: Annotated[str | None, Query(max_length=64)] = None,
) -> Page[SbomPackageRead]:
    service.get_sbom_or_404(db, sbom_id)
    rows, total = service.list_packages(
        db, sbom_id, params, search=search, ecosystem=ecosystem
    )
    return Page.build([SbomPackageRead.model_validate(row) for row in rows], total, params)


@router.get("/sboms/{sbom_id}/download")
def download_sbom(
    sbom_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> Response:
    content, filename, media_type = service.download_sbom(db, sbom_id)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
