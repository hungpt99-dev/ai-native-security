"""OpenAI-compatible chat-completions provider.

Deliberately implemented on ``httpx`` instead of a vendor SDK:

* the request/response surface used here is three fields wide (messages,
  ``response_format``, ``max_tokens``) and stable;
* ``httpx`` is already a pinned dependency, so adding an SDK buys nothing;
* gateways that speak the same protocol (self-hosted, proxy, vendor-compatible)
  work unchanged through ``ANS_AI_BASE_URL`` and ``ANS_AI_EXTRA_HEADERS``.

Structured output is JSON Schema constrained and then re-validated with Pydantic.
A malformed answer is a failure, not an "approximate" success.
"""

from __future__ import annotations

import hashlib
import json
import random
import time
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.modules.ai.errors import (
    AIProviderError,
    AIRateLimitedError,
    AIResponseError,
)
from app.modules.ai.providers.base import AIProvider, RateLimiter
from app.modules.ai.schemas.provider import AIRequest, AIResult, AIUsage, ProviderCapabilities

logger = get_logger(__name__)

SchemaT = TypeVar("SchemaT", bound=BaseModel)

RETRYABLE_STATUS = {408, 409, 429, 500, 502, 503, 504}


def _strictify(schema: dict[str, Any]) -> dict[str, Any]:
    """Make a Pydantic JSON schema acceptable to strict structured outputs.

    OpenAI requires ``additionalProperties: false`` and every property listed in
    ``required`` for each object. Optional fields are expressed by a nullable
    type, which Pydantic already emits.
    """

    def walk(node: Any) -> Any:
        if isinstance(node, list):
            return [walk(item) for item in node]
        if not isinstance(node, dict):
            return node
        result = {key: walk(value) for key, value in node.items() if key not in {"default"}}
        if result.get("type") == "object" or "properties" in result:
            properties = result.get("properties")
            if isinstance(properties, dict):
                result["additionalProperties"] = False
                result["required"] = list(properties.keys())
        return result

    return walk(schema)


class OpenAIProvider(AIProvider):
    name = "openai"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.model = self.settings.ai_model
        self.base_url = self.settings.ai_base_url.rstrip("/")
        self._limiter = RateLimiter(self.settings.ai_requests_per_minute)
        self._strict_supported = True

    # ------------------------------------------------------------- interface
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            structured_output=True,
            json_schema=self._strict_supported,
            max_output_tokens=self.settings.ai_max_output_tokens,
            reports_cost=True,
        )

    def is_configured(self) -> bool:
        return bool(self.settings.ai_enabled and self.settings.ai_api_key)

    def generate(self, request: AIRequest) -> AIResult:
        return self._complete(request, schema=None)

    def generate_structured(self, request: AIRequest, schema: type[SchemaT]) -> AIResult:
        return self._complete(request, schema=schema)

    # ------------------------------------------------------------- internals
    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.settings.ai_api_key or ''}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Extra headers are for gateway routing/affinity. They are configuration,
        # not secrets, and are never logged.
        headers.update(self.settings.ai_extra_headers or {})
        return headers

    def _payload(self, request: AIRequest, schema: type[BaseModel] | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.render_user_message()},
            ],
            "temperature": (
                request.temperature if request.temperature is not None else self.settings.ai_temperature
            ),
            "max_tokens": request.max_output_tokens or self.settings.ai_max_output_tokens,
        }
        if schema is not None:
            schema_name = request.schema_id or schema.__name__
            strict_schema = _strictify(schema.model_json_schema())
            if self._strict_supported:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": schema_name[:64],
                        "strict": True,
                        "schema": strict_schema,
                    },
                }
            else:
                # Gateways that only support json_object do not enforce a schema,
                # so it has to travel in the prompt or the model invents its own
                # key names (which then fails validation).
                payload["response_format"] = {"type": "json_object"}
                payload["messages"][0]["content"] += _schema_instruction(strict_schema)
        return payload

    def _complete(self, request: AIRequest, schema: type[SchemaT] | None) -> AIResult:
        self.ensure_available()
        started = time.perf_counter()
        payload = self._payload(request, schema)
        schema_json = _strictify(schema.model_json_schema()) if schema is not None else None
        try:
            content, usage, request_id, finish_reason, attempts = self._post(
                payload, schema_name=request.schema_id, schema_json=schema_json
            )
        except AIResponseError as exc:
            # Reasoning models can spend the entire completion budget before
            # emitting any content (finish_reason="length"). Retry once with a
            # doubled budget instead of failing a request that is otherwise fine.
            current = int(payload.get("max_tokens") or 0)
            doubled = min(max(current * 2, 2000), 16000)
            if exc.details.get("finish_reason") == "length" and doubled > current:
                payload["max_tokens"] = doubled
                logger.info(
                    "retrying with a larger output budget",
                    extra={
                        "extra_fields": {
                            "provider": self.name,
                            "model": self.model,
                            "max_tokens": doubled,
                        }
                    },
                )
                content, usage, request_id, finish_reason, attempts = self._post(
                    payload, schema_name=request.schema_id, schema_json=schema_json
                )
            else:
                raise

        if schema is None:
            return AIResult(
                text=content,
                usage=usage,
                provider=self.name,
                model=self.model,
                latency_ms=int((time.perf_counter() - started) * 1000),
                request_id=request_id,
                finish_reason=finish_reason,
                attempts=attempts,
            )

        structured, validation_errors = _validate(content, schema)
        if structured is None:
            # One bounded repair attempt: tell the model exactly what was wrong.
            repair_messages = [
                {
                    "role": "system",
                    "content": request.system_prompt,
                },
                {"role": "user", "content": request.render_user_message()},
                {"role": "assistant", "content": content[:4000]},
                {
                    "role": "user",
                    "content": (
                        "Your previous answer did not satisfy the required JSON schema. "
                        "Return ONLY a corrected JSON object. Validation errors:\n"
                        + "\n".join(f"- {error}" for error in validation_errors[:8])
                    ),
                },
            ]
            retry_payload = dict(payload)
            retry_payload["messages"] = repair_messages
            content, usage2, request_id2, finish_reason, attempts2 = self._post(
                retry_payload, schema_name=request.schema_id
            )
            attempts += attempts2
            usage = AIUsage(
                input_tokens=usage.input_tokens + usage2.input_tokens,
                output_tokens=usage.output_tokens + usage2.output_tokens,
                total_tokens=usage.total_tokens + usage2.total_tokens,
                cost_usd=_sum_cost(usage.cost_usd, usage2.cost_usd),
            )
            request_id = request_id2 or request_id
            structured, validation_errors = _validate(content, schema)

        if structured is None:
            raise AIResponseError(
                "Model output did not match the required schema",
                details={
                    "schema": request.schema_id or schema.__name__,
                    "errors": validation_errors[:8],
                    "response_sha256": hashlib.sha256(content.encode()).hexdigest(),
                },
            )

        return AIResult(
            text=content,
            structured=structured.model_dump(mode="json"),
            usage=usage,
            provider=self.name,
            model=self.model,
            latency_ms=int((time.perf_counter() - started) * 1000),
            request_id=request_id,
            finish_reason=finish_reason,
            attempts=attempts,
        )

    def _post(
        self,
        payload: dict[str, Any],
        *,
        schema_name: str | None,
        schema_json: dict[str, Any] | None = None,
    ) -> tuple[str, AIUsage, str | None, str | None, int]:
        url = f"{self.base_url}/chat/completions"
        last_error: str | None = None
        attempts = 0
        for attempt in range(1, self.settings.ai_max_retries + 1):
            attempts = attempt
            self._limiter.acquire()
            try:
                with httpx.Client(timeout=self.settings.ai_timeout_seconds) as client:
                    response = client.post(url, headers=self._headers(), json=payload)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc.__class__.__name__
                logger.warning(
                    "ai provider transport error",
                    extra={
                        "extra_fields": {
                            "provider": self.name,
                            "model": self.model,
                            "attempt": attempt,
                            "error": last_error,
                        }
                    },
                )
                if attempt >= self.settings.ai_max_retries:
                    raise AIProviderError(
                        "AI provider request failed", details={"error": last_error}, retryable=True
                    ) from exc
                self._sleep(attempt)
                continue

            if response.status_code in RETRYABLE_STATUS:
                last_error = f"HTTP {response.status_code}"
                if response.status_code == 429 and attempt >= self.settings.ai_max_retries:
                    raise AIRateLimitedError(
                        "AI provider rate limit exceeded",
                        details={"provider": self.name, "model": self.model},
                    )
                retry_after = _retry_after(response)
                logger.warning(
                    "ai provider retryable response",
                    extra={
                        "extra_fields": {
                            "provider": self.name,
                            "model": self.model,
                            "status": response.status_code,
                            "attempt": attempt,
                            "delay_seconds": retry_after,
                        }
                    },
                )
                if attempt >= self.settings.ai_max_retries:
                    raise AIProviderError(
                        "AI provider returned a retryable error",
                        details={"status": response.status_code, "error": _body_excerpt(response)},
                        retryable=True,
                    )
                time.sleep(retry_after)
                continue

            if response.status_code == 400 and schema_name and self._strict_supported:
                # Some OpenAI-compatible gateways reject the json_schema variant.
                # Degrade the response format once and retry immediately.
                logger.info(
                    "falling back to json_object response format",
                    extra={"extra_fields": {"provider": self.name, "model": self.model}},
                )
                self._strict_supported = False
                payload["response_format"] = {"type": "json_object"}
                if schema_json is not None:
                    payload["messages"][0]["content"] += _schema_instruction(schema_json)
                self._sleep(1)
                continue

            if response.status_code >= 400:
                raise AIProviderError(
                    "AI provider rejected the request",
                    details={
                        "status": response.status_code,
                        "error": _body_excerpt(response),
                    },
                )

            try:
                body = response.json()
            except ValueError as exc:
                raise AIResponseError(
                    "AI provider returned a non-JSON response",
                    details={"status": response.status_code},
                ) from exc

            choice = (body.get("choices") or [{}])[0] or {}
            message = choice.get("message") or {}
            content = message.get("content") or ""
            finish_reason = choice.get("finish_reason")
            if not content.strip():
                # Reasoning models can spend the whole budget on hidden tokens.
                # That is a failure to produce output, not an empty success.
                raw_usage = body.get("usage") or {}
                raise AIResponseError(
                    "AI provider returned an empty completion",
                    details={
                        "finish_reason": finish_reason,
                        "reasoning_only": bool(message.get("reasoning_content")),
                        "completion_tokens": raw_usage.get("completion_tokens"),
                        "reasoning_tokens": (
                            (raw_usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
                        ),
                        "max_tokens": payload.get("max_tokens"),
                    },
                )
            usage = _usage_from(body.get("usage") or {}, self.settings)
            logger.info(
                "ai provider call",
                extra={
                    "extra_fields": {
                        "provider": self.name,
                        "model": self.model,
                        "status": response.status_code,
                        "attempt": attempt,
                        "input_tokens": usage.input_tokens,
                        "output_tokens": usage.output_tokens,
                        "cost_usd": usage.cost_usd,
                        "finish_reason": finish_reason,
                    }
                },
            )
            return content, usage, body.get("id"), finish_reason, attempts

        raise AIProviderError("AI provider request failed after retries", details={"error": last_error})

    def _sleep(self, attempt: int) -> None:
        base = self.settings.ai_retry_backoff_seconds * (2 ** (attempt - 1))
        # Jitter only: spreading retries is not a security decision.
        time.sleep(min(30.0, base) * (0.5 + random.random() / 2))  # noqa: S311


def _schema_instruction(schema_json: dict[str, Any]) -> str:
    return (
        "\n\nReturn ONLY a JSON object that validates against this JSON Schema "
        "(all required properties present, no extra properties):\n"
        + json.dumps(schema_json, sort_keys=True)
    )


def _validate[SchemaT: BaseModel](content: str, schema: type[SchemaT]) -> tuple[SchemaT | None, list[str]]:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        data = json.loads(text)
    except ValueError as exc:
        return None, [f"invalid JSON: {exc}"]
    try:
        return schema.model_validate(data), []
    except ValidationError as exc:
        errors = [
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}" for error in exc.errors()[:8]
        ]
        return None, errors


def _usage_from(raw: dict[str, Any], settings: Settings) -> AIUsage:
    input_tokens = int(raw.get("prompt_tokens") or raw.get("input_tokens") or 0)
    output_tokens = int(raw.get("completion_tokens") or raw.get("output_tokens") or 0)
    total = int(raw.get("total_tokens") or input_tokens + output_tokens)
    cost = raw.get("cost")
    if not isinstance(cost, (int, float)) or cost <= 0:
        gateway = raw.get("opencode") if isinstance(raw.get("opencode"), dict) else {}
        list_cost = gateway.get("list_cost") if isinstance(gateway, dict) else None
        cost = list_cost if isinstance(list_cost, (int, float)) else None
    if not isinstance(cost, (int, float)) or cost <= 0:
        if settings.ai_price_input_per_1k or settings.ai_price_output_per_1k:
            cost = (
                input_tokens / 1000 * settings.ai_price_input_per_1k
                + output_tokens / 1000 * settings.ai_price_output_per_1k
            )
        else:
            cost = None
    return AIUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total,
        cost_usd=round(float(cost), 8) if isinstance(cost, (int, float)) else None,
    )


def _sum_cost(left: float | None, right: float | None) -> float | None:
    if left is None and right is None:
        return None
    return round((left or 0.0) + (right or 0.0), 8)


def _retry_after(response: httpx.Response) -> float:
    header = response.headers.get("Retry-After")
    if header:
        try:
            return min(60.0, max(0.5, float(header)))
        except ValueError:
            pass
    return 2.0 + random.random()  # noqa: S311 - jitter, not secrecy


def _body_excerpt(response: httpx.Response) -> str:
    try:
        body = response.json()
        if isinstance(body, dict):
            error = body.get("error")
            if isinstance(error, dict):
                return str(error.get("message") or error)[:400]
            return json.dumps(body)[:400]
    except ValueError:
        pass
    return response.text[:400]
