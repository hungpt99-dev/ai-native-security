"""System status API: health, capability and scanner availability."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.config import get_settings
from app.core.storage import get_storage
from app.database.session import get_db
from app.modules.scanners.registry import scanner_status
from app.modules.scans.models import ScannerExecution

router = APIRouter(prefix="/system", tags=["system"])

_started_at = time.time()
#: A scanner execution is considered fresh evidence for this long. This matters
#: because the API container does not ship the scanner binaries — only the
#: worker does — so a local probe alone would be misleading.
FRESH_EXECUTION_WINDOW = timedelta(days=7)


@router.get("/info")
def system_info(principal: CurrentPrincipal) -> dict[str, Any]:
    settings = get_settings()
    from app.modules.ai.providers.registry import provider_status

    ai = provider_status()
    # Never expose the key itself, only whether one is present.
    ai.pop("base_url", None)
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "auth_enabled": settings.auth_enabled,
        "uptime_seconds": round(time.time() - _started_at, 1),
        "scanners_enabled": settings.scanners_enabled,
        "storage_backend": settings.storage_backend,
        "ai": ai,
    }


@router.get("/scanners")
def scanners(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> list[dict[str, Any]]:
    """Scanner availability.

    Combines a local binary probe with the most recent execution recorded by a
    worker, so the dashboard stays accurate when the API process cannot see the
    scanner binaries (the normal Docker deployment).
    """
    statuses = scanner_status()
    threshold = datetime.now(UTC) - FRESH_EXECUTION_WINDOW
    for entry in statuses:
        name = str(entry["scanner"])
        execution = db.execute(
            select(ScannerExecution)
            .where(ScannerExecution.scanner == name)
            .order_by(ScannerExecution.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if execution is None:
            entry["last_execution"] = None
            continue
        last_run = {
            "scan_id": str(execution.scan_id),
            "status": execution.status,
            "version": execution.version,
            "finished_at": execution.finished_at.isoformat() if execution.finished_at else None,
            "duration_seconds": execution.duration_seconds,
        }
        entry["last_execution"] = last_run
        reference_time = execution.finished_at or execution.created_at
        fresh = reference_time is not None and reference_time >= threshold
        if not entry["available"] and fresh and execution.status == "SUCCESS":
            entry["available"] = True
            entry["version"] = entry.get("version") or execution.version
            entry["source"] = "worker"
            entry["probe_error"] = entry.get("error")
            entry["error"] = None
        else:
            entry["source"] = "api" if entry["available"] else "none"
    return statuses


@router.get("/dependencies")
def dependencies(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> dict[str, Any]:
    status: dict[str, Any] = {"database": "ok", "storage": "unknown"}
    try:
        db.execute(text("SELECT 1"))
        status["database"] = "ok"
    except Exception as exc:  # pragma: no cover - infra failure path
        status["database"] = f"error: {exc}"
    try:
        get_storage()  # fail fast if the backend is misconfigured
        status["storage"] = "ok" if get_settings().storage_root.exists() else "missing"
    except Exception as exc:  # pragma: no cover
        status["storage"] = f"error: {exc}"
    return status
