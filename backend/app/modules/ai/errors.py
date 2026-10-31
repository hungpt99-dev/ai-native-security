"""AI layer error types.

They map onto the application's existing error envelope so clients see the same
``{"error": {code, message, details}}`` shape everywhere.
"""

from __future__ import annotations

from typing import Any

from fastapi import status

from app.core.errors import AppError


class AIUnavailableError(AppError):
    """AI is disabled or has no credentials. Deterministic features keep working."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "ai_unavailable"


class AIProviderError(AppError):
    """Upstream model provider failed (auth, bad request, 5xx after retries)."""

    status_code = status.HTTP_502_BAD_GATEWAY
    code = "ai_provider_error"

    def __init__(
        self, message: str, *, details: dict[str, Any] | None = None, retryable: bool = False
    ) -> None:
        super().__init__(message, details=details)
        self.retryable = retryable


class AIResponseError(AppError):
    """The model answered but not with valid, schema-conforming output."""

    status_code = status.HTTP_502_BAD_GATEWAY
    code = "ai_invalid_response"


class AIRateLimitedError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "ai_rate_limited"


class AIBudgetExceededError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "ai_budget_exceeded"


class AIGuardrailError(AppError):
    """A request was refused before it reached the provider."""

    status_code = 422
    code = "ai_guardrail_violation"
