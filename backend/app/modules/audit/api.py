"""Audit trail API (read-only by design)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.audit import service

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    status_code: int | None
    request_id: str | None
    ip_address: str | None
    detail: dict[str, Any] = Field(default_factory=dict)


@router.get("", response_model=Page[AuditRead])
def list_audit(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    params: Annotated[PageParams, Depends(page_params)],
    actor: Annotated[str | None, Query(max_length=120)] = None,
    action: Annotated[str | None, Query(max_length=24)] = None,
    resource_type: Annotated[str | None, Query(max_length=64)] = None,
    resource_id: Annotated[str | None, Query(max_length=120)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> Page[AuditRead]:
    rows, total = service.list_logs(
        db,
        params,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        search=search,
    )
    return Page.build([AuditRead.model_validate(row) for row in rows], total, params)
