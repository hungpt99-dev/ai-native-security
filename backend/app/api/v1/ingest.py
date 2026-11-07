"""Event ingestion endpoints.

Mounted outside the API-key router: a sensor (Falco, a log shipper) authenticates
with a dedicated shared token, not with a human API key. When
``ANS_EVENTS_INGEST_TOKEN`` is unset the endpoints answer 503 — an unconfigured
ingestion path must not accept anonymous security telemetry.

Payloads are bounded before parsing; the normalization layer bounds and redacts
every stored field.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import Principal
from app.core.config import get_settings
from app.core.errors import AuthenticationError, ServiceUnavailableError, ValidationError
from app.core.security import constant_time_equals
from app.database.session import get_db
from app.modules.events import service as events_service

router = APIRouter(prefix="/ingest", tags=["ingestion"])

MAX_BODY_BYTES = 2 * 1024 * 1024


class GenericEvent(BaseModel):
    event_type: str = Field(min_length=1, max_length=160)
    title: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, max_length=4000)
    category: str | None = Field(default=None, max_length=24)
    severity: str | None = Field(default=None, max_length=16)
    source_event_id: str | None = Field(default=None, max_length=200)
    occurred_at: str | None = Field(default=None, max_length=64)
    normalized: dict[str, Any] = Field(default_factory=dict)
    indicators: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    raw: dict[str, Any] = Field(default_factory=dict)


class GenericBatch(BaseModel):
    events: list[GenericEvent] = Field(min_length=1)


def require_ingest_token(
    x_ingest_token: Annotated[str | None, Header(alias="X-ANS-Ingest-Token")] = None,
) -> Principal:
    settings = get_settings()
    if not settings.events_ingest_token:
        raise ServiceUnavailableError(
            "Event ingestion is not configured", details={"setting": "ANS_EVENTS_INGEST_TOKEN"}
        )
    if not x_ingest_token or not constant_time_equals(settings.events_ingest_token, x_ingest_token):
        raise AuthenticationError("Invalid ingestion token")
    return Principal(subject="event-sensor", is_authenticated=True)


async def _read_json(request: Request) -> Any:
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
        raise ValidationError("Ingestion payload is too large")
    body = await request.body()
    if not body:
        raise ValidationError("Ingestion payload is empty")
    if len(body) > MAX_BODY_BYTES:
        raise ValidationError("Ingestion payload is too large")
    try:
        import json

        return json.loads(body)
    except ValueError as exc:
        raise ValidationError("Ingestion payload is not valid JSON") from exc


@router.post("/falco", status_code=status.HTTP_202_ACCEPTED)
async def ingest_falco(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_ingest_token)],
) -> dict[str, Any]:
    """Falco HTTP output (single alert object or a JSON array)."""
    payload = await _read_json(request)
    request.state.ingest_actor = "falco"
    batch = payload if isinstance(payload, list) else [payload]
    settings = get_settings()
    if len(batch) > settings.events_max_batch:
        raise ValidationError(
            "Falco batch exceeds the configured maximum",
            details={"max": settings.events_max_batch},
        )
    return events_service.ingest_falco(db, payload, actor="falco")


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(
    request: Request,
    batch: GenericBatch,
    db: Annotated[Session, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_ingest_token)],
) -> dict[str, Any]:
    """Generic normalized event ingestion (see docs/RUNTIME_SECURITY.md)."""
    settings = get_settings()
    request.state.ingest_actor = "event-sensor"
    if len(batch.events) > settings.events_max_batch:
        raise ValidationError(
            "Batch exceeds the configured maximum",
            details={"max": settings.events_max_batch},
        )
    return events_service.ingest_generic(
        db, [event.model_dump(exclude_none=True) for event in batch.events], actor="event-sensor"
    )


@router.get("/health")
def ingest_health() -> dict[str, Any]:
    settings = get_settings()
    return {
        "configured": bool(settings.events_ingest_token),
        "max_batch": settings.events_max_batch,
    }
