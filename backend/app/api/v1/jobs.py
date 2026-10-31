"""Job queue and schedule inspection/administration API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.errors import NotFoundError
from app.core.pagination import Page, PageParams, page_params, paginate
from app.database.session import get_db
from app.workers.models import Job, Schedule

router = APIRouter(tags=["operations"])


class JobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    status: str
    payload: dict
    attempts: int
    max_attempts: int
    run_after: datetime
    finished_at: datetime | None
    last_error: str | None
    created_at: datetime


class ScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    payload: dict
    interval_seconds: int
    enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime | None
    last_status: str | None
    last_error: str | None


class ScheduleUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = None


@router.get("/jobs", response_model=Page[JobRead])
def list_jobs(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    status: Annotated[str | None, Query()] = None,
    kind: Annotated[str | None, Query()] = None,
) -> Page[JobRead]:
    stmt = select(Job)
    if status:
        stmt = stmt.where(Job.status == status.upper())
    if kind:
        stmt = stmt.where(Job.kind == kind.upper())
    stmt = stmt.order_by(Job.created_at.desc())
    rows, total = paginate(db, stmt, params)
    return Page.build([JobRead.model_validate(row) for row in rows], total, params)


@router.get("/schedules", response_model=list[ScheduleRead])
def list_schedules(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> list[ScheduleRead]:
    rows = db.execute(select(Schedule).order_by(Schedule.name)).scalars().all()
    return [ScheduleRead.model_validate(row) for row in rows]


@router.patch("/schedules/{schedule_id}", response_model=ScheduleRead)
def update_schedule(
    schedule_id: uuid.UUID,
    payload: ScheduleUpdate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> ScheduleRead:
    schedule = db.get(Schedule, schedule_id)
    if schedule is None:
        raise NotFoundError("Schedule not found", details={"schedule_id": str(schedule_id)})
    if payload.enabled is not None:
        schedule.enabled = payload.enabled
    if payload.interval_seconds is not None:
        schedule.interval_seconds = max(60, payload.interval_seconds)
    db.commit()
    return ScheduleRead.model_validate(schedule)
