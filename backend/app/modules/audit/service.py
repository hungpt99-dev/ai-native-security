"""Audit recording.

Two paths write here:

1. ``AuditMiddleware`` records every mutating API request (who, what, outcome,
   request id) without touching the request body — a body can contain a token or
   a secret, and the audit trail is not a request log.
2. Services call :func:`record` for domain events that deserve a durable entry
   (an incident opened by a detection rule, an ingestion batch, a scan started).

Audit writes never break the request they describe: a failure is logged and
swallowed, because losing an audit row must not turn a successful action into an
error the caller retries.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger, request_id_var
from app.core.pagination import PageParams, paginate
from app.core.security import redact_text
from app.modules.audit.models import AuditLog

logger = get_logger(__name__)

_UUID_PATH = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.IGNORECASE
)
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
#: Paths whose POST is an execution/ingestion rather than a creation.
_EXECUTE_SUFFIXES = ("/trigger", "/scan", "/verify", "/investigate", "/correlate", "/run")


def _now() -> datetime:
    return datetime.now(UTC)


def record(
    db: Session,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    status_code: int | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        id=uuid.uuid4(),
        actor=(actor or "anonymous")[:120],
        action=action[:24],
        resource_type=resource_type[:64],
        resource_id=str(resource_id)[:120] if resource_id else None,
        status_code=status_code,
        request_id=(request_id or "")[:64] or None,
        ip_address=(ip_address or "")[:64] or None,
        detail=_bounded(detail or {}),
    )
    db.add(entry)
    return entry


def _bounded(detail: dict[str, Any], limit: int = 40) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in list(detail.items())[:limit]:
        if isinstance(value, str):
            safe[str(key)[:60]] = redact_text(value[:500])
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[str(key)[:60]] = value
        elif isinstance(value, (list, dict)):
            safe[str(key)[:60]] = redact_text(repr(value)[:500])
        else:
            safe[str(key)[:60]] = redact_text(str(value)[:200])
    return safe


def list_logs(
    db: Session,
    params: PageParams,
    *,
    actor: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    search: str | None = None,
) -> tuple[list[AuditLog], int]:
    stmt = select(AuditLog)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action == action.upper())
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
    if search:
        like = f"%{search.strip()[:200]}%"
        stmt = stmt.where(
            or_(AuditLog.resource_type.ilike(like), AuditLog.resource_id.ilike(like))
        )
    stmt = stmt.order_by(AuditLog.created_at.desc())
    return paginate(db, stmt, params)


def _resource(path: str, prefix: str) -> tuple[str, str | None]:
    relative = path[len(prefix) :] if path.startswith(prefix) else path
    segments = [segment for segment in relative.split("/") if segment]
    resource_type = segments[0] if segments else "api"
    resource_id = next(
        (segment for segment in segments[1:] if _UUID_PATH.fullmatch(f"/{segment}")), None
    )
    return resource_type, resource_id


def _action_for(method: str, path: str) -> str:
    if method == "POST":
        if "/ingest/" in path:
            return "INGEST"
        if any(path.endswith(suffix) or f"{suffix}/" in path for suffix in _EXECUTE_SUFFIXES):
            return "EXECUTE"
        return "CREATE"
    if method in {"PUT", "PATCH"}:
        return "UPDATE"
    return "DELETE"


async def audit_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = await call_next(request)
    if request.method not in _MUTATING:
        return response

    settings = get_settings()
    if not request.url.path.startswith(settings.api_v1_prefix):
        return response

    try:
        from app.database.session import SessionLocal

        principal = getattr(request.state, "principal", None)
        actor = getattr(principal, "subject", None) or getattr(
            request.state, "ingest_actor", None
        ) or "anonymous"
        resource_type, resource_id = _resource(request.url.path, settings.api_v1_prefix)
        with SessionLocal() as db:
            record(
                db,
                actor=actor,
                action=_action_for(request.method, request.url.path),
                resource_type=resource_type,
                resource_id=resource_id,
                status_code=response.status_code,
                request_id=request_id_var.get(),
                ip_address=request.client.host if request.client else None,
                detail={
                    "method": request.method,
                    "path": request.url.path,
                    "query": redact_text(str(request.url.query)[:300]),
                },
            )
            db.commit()
    except Exception:  # never fail the action because its audit row failed
        logger.exception("audit record failed")
    return response
