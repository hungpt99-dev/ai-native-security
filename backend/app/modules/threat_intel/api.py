"""Threat intelligence API: indicator ingestion, search, freshness."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.enums import INDICATOR_SOURCES, INDICATOR_TYPES, IndicatorSource
from app.core.errors import ValidationError
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.audit import service as audit
from app.modules.threat_intel import service

router = APIRouter(prefix="/threat-intel", tags=["threat-intelligence"])


class IndicatorInput(BaseModel):
    indicator_type: str = Field(max_length=16)
    value: str = Field(min_length=1, max_length=512)
    severity: str = Field(default="HIGH", max_length=16)
    confidence: int = Field(default=50, ge=0, le=100)
    description: str | None = Field(default=None, max_length=4000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    expires_at: datetime | None = None
    source_ref: str | None = Field(default=None, max_length=200)


class IndicatorBatch(BaseModel):
    source: str = Field(default=IndicatorSource.MANUAL.value, max_length=32)
    indicators: list[IndicatorInput] = Field(min_length=1, max_length=1000)


class IndicatorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    indicator_type: str
    value: str
    source: str
    source_ref: str | None
    severity: str
    confidence: int
    description: str | None
    tags: list[str]
    active: bool
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    expires_at: datetime | None
    ingested_at: datetime
    created_at: datetime


@router.get("/indicators", response_model=Page[IndicatorRead])
def list_indicators(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    params: Annotated[PageParams, Depends(page_params)],
    indicator_type: Annotated[str | None, Query()] = None,
    source: Annotated[str | None, Query()] = None,
    value: Annotated[str | None, Query(max_length=200)] = None,
    active: Annotated[bool | None, Query()] = None,
) -> Page[IndicatorRead]:
    if indicator_type and indicator_type.upper() not in INDICATOR_TYPES:
        raise ValidationError("Unknown indicator type")
    if source and source.upper() not in INDICATOR_SOURCES:
        raise ValidationError("Unknown indicator source")
    rows, total = service.list_indicators(
        db, params, indicator_type=indicator_type, source=source, value=value, active=active
    )
    return Page.build([IndicatorRead.model_validate(row) for row in rows], total, params)


@router.post("/indicators", status_code=status.HTTP_201_CREATED)
def ingest_indicators(
    payload: IndicatorBatch,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    result = service.upsert_indicators(
        db,
        [item.model_dump() for item in payload.indicators],
        source=payload.source.upper(),
        actor=principal.subject,
    )
    audit.record(
        db,
        actor=principal.subject,
        action="INGEST",
        resource_type="threat_indicators",
        detail={key: value for key, value in result.items() if key != "errors"},
    )
    return result


@router.post("/indicators/{indicator_id}/deactivate", response_model=IndicatorRead)
def deactivate_indicator(
    indicator_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> IndicatorRead:
    indicator = service.deactivate(db, indicator_id)
    audit.record(
        db,
        actor=principal.subject,
        action="UPDATE",
        resource_type="threat_indicators",
        resource_id=indicator.id,
        detail={"active": False},
    )
    return IndicatorRead.model_validate(indicator)


@router.get("/summary")
def indicator_summary(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> dict[str, Any]:
    return service.summary(db)
