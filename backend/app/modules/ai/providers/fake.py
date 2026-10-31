"""Deterministic provider used by the test suite and by ``ANS_AI_PROVIDER=fake``.

It is a real ``AIProvider`` implementation — same validation, same result shape —
so tests exercise the actual call path without a network or a key. It is never
selected implicitly: a deployment that has no key raises ``AIUnavailableError``
instead of silently producing model-looking output.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from app.modules.ai.errors import AIProviderError, AIResponseError
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.schemas.provider import AIRequest, AIResult, AIUsage, ProviderCapabilities

SchemaT = TypeVar("SchemaT", bound=BaseModel)

Responder = Callable[[AIRequest, type[BaseModel] | None], Any]


class FakeProvider(AIProvider):
    name = "fake"

    def __init__(
        self,
        responses: list[Any] | None = None,
        *,
        responder: Responder | None = None,
        configured: bool = True,
        cost_per_call: float | None = 0.0,
    ) -> None:
        self.responses = list(responses or [])
        self.responder = responder
        self.configured = configured
        self.cost_per_call = cost_per_call
        self.requests: list[AIRequest] = []

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(structured_output=True, json_schema=True, reports_cost=True)

    def is_configured(self) -> bool:
        return self.configured

    def generate(self, request: AIRequest) -> AIResult:
        return self._respond(request, None)

    def generate_structured(self, request: AIRequest, schema: type[SchemaT]) -> AIResult:
        return self._respond(request, schema)

    # ------------------------------------------------------------------ internal
    def _respond(self, request: AIRequest, schema: type[BaseModel] | None) -> AIResult:
        self.ensure_available()
        self.requests.append(request)
        started = time.perf_counter()
        payload: Any
        if self.responder is not None:
            payload = self.responder(request, schema)
        elif self.responses:
            payload = self.responses.pop(0)
        else:
            payload = {} if schema is not None else ""

        if isinstance(payload, Exception):
            raise payload
        if callable(payload) and not isinstance(payload, (dict, str, BaseModel)):
            payload = payload(request, schema)

        structured: dict[str, Any] | None = None
        text: str
        if schema is not None:
            if isinstance(payload, BaseModel):
                structured = payload.model_dump(mode="json")
            elif isinstance(payload, str):
                import json

                try:
                    parsed = json.loads(payload)
                except ValueError as exc:
                    raise AIResponseError(
                        "Invalid JSON from fake provider", details={"error": str(exc)}
                    ) from exc
                structured = parsed
            elif isinstance(payload, (dict, list)):
                if isinstance(payload, list):
                    raise AIResponseError("Expected a JSON object, got an array")
                structured = payload
            else:
                raise AIProviderError("Unsupported fake payload")
            try:
                structured = schema.model_validate(structured).model_dump(mode="json")
            except ValidationError as exc:
                raise AIResponseError(
                    "Fake provider output does not match schema",
                    details={"errors": [str(error["msg"]) for error in exc.errors()]},
                ) from exc
            import json as _json

            text = _json.dumps(structured)
        else:
            text = payload if isinstance(payload, str) else str(payload)

        return AIResult(
            text=text,
            structured=structured,
            usage=AIUsage(
                input_tokens=request.input_chars() // 4,
                output_tokens=len(text) // 4,
                total_tokens=0,
                cost_usd=self.cost_per_call,
            ),
            provider=self.name,
            model="fake-model",
            latency_ms=int((time.perf_counter() - started) * 1000),
            request_id="fake-request",
            finish_reason="stop",
            attempts=1,
        )
