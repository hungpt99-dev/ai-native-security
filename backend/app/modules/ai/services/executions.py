"""Execution ledger: one row per model call, success or failure.

This is what makes the AI layer auditable. It stores identifiers, usage and cost —
never prompts, evidence text or credentials.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AIExecutionStatus
from app.core.logging import get_logger
from app.modules.ai.errors import (
    AIBudgetExceededError,
    AIProviderError,
    AIRateLimitedError,
    AIResponseError,
    AIUnavailableError,
)
from app.modules.ai.models import AIExecution
from app.modules.ai.schemas.provider import AIRequest, AIResult

logger = get_logger(__name__)


def prompt_fingerprint(request: AIRequest) -> str:
    """Hash of the system prompt + instruction *template* (never the evidence)."""
    material = f"{request.prompt_id}:{request.prompt_version}:{request.system_prompt}:{request.instruction}"
    return hashlib.sha256(material.encode()).hexdigest()


def record_result(execution: AIExecution, result: AIResult) -> None:
    execution.model = result.model or execution.model
    execution.provider = result.provider or execution.provider
    execution.input_tokens = result.usage.input_tokens
    execution.output_tokens = result.usage.output_tokens
    execution.cost_usd = result.usage.cost_usd
    execution.request_id = result.request_id
    execution.attempts = max(1, result.attempts)
    execution.execution_metadata = {
        **(execution.execution_metadata or {}),
        "finish_reason": result.finish_reason,
        "latency_ms": result.latency_ms,
    }


def _classify(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, AIUnavailableError):
        return AIExecutionStatus.NOT_CONFIGURED.value, "ai_unavailable"
    if isinstance(exc, AIBudgetExceededError):
        return AIExecutionStatus.BUDGET_EXCEEDED.value, "ai_budget_exceeded"
    if isinstance(exc, AIRateLimitedError):
        return AIExecutionStatus.RATE_LIMITED.value, "ai_rate_limited"
    if isinstance(exc, AIResponseError):
        return AIExecutionStatus.INVALID_OUTPUT.value, exc.code
    if isinstance(exc, AIProviderError):
        code = "ai_timeout" if "timeout" in str(exc).lower() else exc.code
        status = AIExecutionStatus.TIMED_OUT.value if code == "ai_timeout" else AIExecutionStatus.FAILED.value
        return status, code
    return AIExecutionStatus.FAILED.value, "internal_error"


@contextmanager
def track_execution(
    db: Session,
    *,
    kind: str,
    request: AIRequest | None = None,
    provider_name: str = "",
    model: str = "",
    finding_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    context_snapshot_id: uuid.UUID | None = None,
    principal: str = "system",
    schema_id: str | None = None,
) -> Iterator[AIExecution]:
    """Persist a RUNNING row before the call, then finalise it either way.

    The row is committed before the model call so a crash (OOM, kill) still
    leaves evidence that a call was started.
    """
    settings = get_settings()
    execution = AIExecution(
        kind=kind,
        status=AIExecutionStatus.RUNNING.value,
        provider=provider_name,
        model=model,
        prompt_id=request.prompt_id if request else "",
        prompt_version=request.prompt_version if request else "",
        prompt_sha256=prompt_fingerprint(request) if request else "",
        schema_id=schema_id or (request.schema_id if request else None),
        schema_version=request.schema_version if request else None,
        finding_id=finding_id,
        asset_id=asset_id,
        context_snapshot_id=context_snapshot_id,
        principal=principal,
        started_at=datetime.now(UTC),
        input_chars=request.input_chars() if request else None,
        execution_metadata={"ai_store_prompts": settings.ai_store_prompts},
    )
    db.add(execution)
    db.commit()
    started = time.perf_counter()
    try:
        yield execution
    except BaseException as exc:  # noqa: BLE001 - classify, then re-raise
        status, code = _classify(exc)
        execution.status = status
        execution.error_code = code
        execution.error_message = str(exc)[:2000]
        execution.finished_at = datetime.now(UTC)
        execution.duration_ms = int((time.perf_counter() - started) * 1000)
        db.commit()
        logger.warning(
            "ai execution failed",
            extra={
                "extra_fields": {
                    "execution_id": str(execution.id),
                    "kind": kind,
                    "status": status,
                    "error_code": code,
                    "duration_ms": execution.duration_ms,
                }
            },
        )
        raise
    else:
        execution.status = AIExecutionStatus.SUCCEEDED.value
        execution.finished_at = datetime.now(UTC)
        execution.duration_ms = int((time.perf_counter() - started) * 1000)
        db.commit()
        logger.info(
            "ai execution finished",
            extra={
                "extra_fields": {
                    "execution_id": str(execution.id),
                    "kind": kind,
                    "model": execution.model,
                    "duration_ms": execution.duration_ms,
                    "input_tokens": execution.input_tokens,
                    "output_tokens": execution.output_tokens,
                    "cost_usd": float(execution.cost_usd) if execution.cost_usd is not None else None,
                }
            },
        )


def to_dict(execution: AIExecution) -> dict[str, Any]:
    return {
        "id": str(execution.id),
        "kind": execution.kind,
        "status": execution.status,
        "provider": execution.provider,
        "model": execution.model,
        "prompt_id": execution.prompt_id,
        "prompt_version": execution.prompt_version,
        "prompt_sha256": execution.prompt_sha256,
        "schema_id": execution.schema_id,
        "schema_version": execution.schema_version,
        "finding_id": str(execution.finding_id) if execution.finding_id else None,
        "asset_id": str(execution.asset_id) if execution.asset_id else None,
        "context_snapshot_id": str(execution.context_snapshot_id) if execution.context_snapshot_id else None,
        "input_tokens": execution.input_tokens,
        "output_tokens": execution.output_tokens,
        "cost_usd": float(execution.cost_usd) if execution.cost_usd is not None else None,
        "duration_ms": execution.duration_ms,
        "attempts": execution.attempts,
        "error_code": execution.error_code,
        "started_at": execution.started_at.isoformat() if execution.started_at else None,
        "finished_at": execution.finished_at.isoformat() if execution.finished_at else None,
    }
