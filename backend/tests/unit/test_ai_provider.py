"""Provider behaviour: structured output, retries, degradation, error mapping.

No network: ``httpx.Client`` is replaced with a scripted stub, so the real
request-building and validation code runs.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from app.core.config import Settings
from app.modules.ai.errors import (
    AIProviderError,
    AIRateLimitedError,
    AIResponseError,
    AIUnavailableError,
)
from app.modules.ai.prompts import get_prompt
from app.modules.ai.providers import openai as openai_module
from app.modules.ai.providers.openai import OpenAIProvider, _strictify
from app.modules.ai.schemas.outputs import RiskAssessmentOutput
from app.modules.ai.schemas.provider import AIRequest, EvidenceBlock


class StubResponse:
    def __init__(
        self,
        status_code: int,
        payload: Any = None,
        *,
        headers: dict[str, str] | None = None,
        text: str | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = text if text is not None else json.dumps(payload or {})

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class StubClient:
    def __init__(self, responses: list[StubResponse], calls: list[dict[str, Any]]) -> None:
        self.responses = responses
        self.calls = calls

    def __enter__(self) -> StubClient:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def post(
        self, url: str, headers: dict[str, str] | None = None, json: dict[str, Any] | None = None
    ) -> StubResponse:
        # Record a copy: the provider mutates its payload between attempts.
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "json": copy.deepcopy(json) if json is not None else None,
            }
        )
        if not self.responses:
            raise AssertionError("stub ran out of responses")
        return self.responses.pop(0)


def chat_response(
    content: str, *, finish_reason: str = "stop", usage: dict[str, Any] | None = None
) -> StubResponse:
    return StubResponse(
        200,
        {
            "id": "req-1",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": finish_reason,
                    "message": {"role": "assistant", "content": content},
                }
            ],
            "usage": usage
            or {"prompt_tokens": 120, "completion_tokens": 40, "total_tokens": 160, "cost": 0.00021},
        },
    )


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        ai_enabled=True,
        ai_provider="openai",
        ai_api_key="sk-test-key-0123456789",
        ai_base_url="https://llm.example.test/v1",
        ai_model="test-model",
        ai_max_retries=2,
        ai_retry_backoff_seconds=0,
        ai_requests_per_minute=600,
        ai_extra_headers={"x-session": "abc"},
    )


@pytest.fixture()
def install_stub(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict[str, Any]] = []
    responses: list[StubResponse] = []

    def _install(*items: StubResponse) -> list[dict[str, Any]]:
        responses.extend(items)
        monkeypatch.setattr(openai_module.httpx, "Client", lambda *a, **k: StubClient(responses, calls))
        monkeypatch.setattr(openai_module.time, "sleep", lambda _seconds: None)
        return calls

    return _install


def _valid_risk_payload() -> dict[str, Any]:
    return {
        "risk_level": "HIGH",
        "risk_score": 78,
        "confidence": 0.7,
        "summary": "Public-facing service uses a vulnerable library.",
        "impact_analysis": "Remote code execution is possible.",
        "exploitability_analysis": "Listed in CISA KEV.",
        "affected_components": ["api"],
        "evidence": [{"key": "E1", "note": "installed version in range"}],
        "missing_information": [],
        "recommended_actions": ["Upgrade to the fixed release"],
        "requires_human_review": True,
    }


def _request() -> AIRequest:
    prompt = get_prompt("risk.assessment")
    return prompt.build(
        instruction="Assess this finding.",
        evidence=[EvidenceBlock(key="E1", source="trivy", locator="package.json", text="lodash 4.17.20")],
    )


def test_structured_output_is_validated(settings: Settings, install_stub) -> None:
    calls = install_stub(chat_response(json.dumps(_valid_risk_payload())))
    provider = OpenAIProvider(settings)
    result = provider.generate_structured(_request(), RiskAssessmentOutput)

    assert result.structured is not None
    assert result.structured["risk_level"] == "HIGH"
    assert result.usage.input_tokens == 120
    assert result.usage.cost_usd == pytest.approx(0.00021)
    sent = calls[0]["json"]
    assert sent["response_format"]["type"] == "json_schema"
    assert sent["response_format"]["json_schema"]["strict"] is True
    assert calls[0]["headers"]["Authorization"].startswith("Bearer ")
    assert calls[0]["headers"]["x-session"] == "abc"


def test_untrusted_evidence_is_fenced(settings: Settings, install_stub) -> None:
    calls = install_stub(chat_response(json.dumps(_valid_risk_payload())))
    provider = OpenAIProvider(settings)
    provider.generate_structured(_request(), RiskAssessmentOutput)
    user_message = calls[0]["json"]["messages"][1]["content"]
    assert "<<<EVIDENCE E1" in user_message
    assert "UNTRUSTED DATA" in user_message


def test_retries_transient_failure_then_succeeds(settings: Settings, install_stub) -> None:
    calls = install_stub(
        StubResponse(503, {"error": {"message": "upstream down"}}),
        chat_response(json.dumps(_valid_risk_payload()), usage={"prompt_tokens": 1, "completion_tokens": 1}),
    )
    provider = OpenAIProvider(settings)
    result = provider.generate_structured(_request(), RiskAssessmentOutput)
    assert result.attempts == 2
    assert len(calls) == 2


def test_rate_limit_exhaustion_maps_to_rate_limited(settings: Settings, install_stub) -> None:
    install_stub(
        StubResponse(429, {"error": {"message": "slow down"}}, headers={"Retry-After": "0"}),
        StubResponse(429, {"error": {"message": "slow down"}}, headers={"Retry-After": "0"}),
    )
    provider = OpenAIProvider(settings)
    with pytest.raises(AIRateLimitedError):
        provider.generate(_request())


def test_server_error_exhaustion_maps_to_provider_error(settings: Settings, install_stub) -> None:
    install_stub(
        StubResponse(500, {"error": {"message": "boom"}}, headers={"Retry-After": "0"}),
        StubResponse(500, {"error": {"message": "boom"}}, headers={"Retry-After": "0"}),
    )
    provider = OpenAIProvider(settings)
    with pytest.raises(AIProviderError):
        provider.generate(_request())


def test_json_schema_rejection_falls_back_to_json_object(settings: Settings, install_stub) -> None:
    calls = install_stub(
        StubResponse(400, {"error": {"message": "response_format json_schema unsupported"}}),
        chat_response(json.dumps(_valid_risk_payload())),
    )
    provider = OpenAIProvider(settings)
    result = provider.generate_structured(_request(), RiskAssessmentOutput)
    assert result.structured is not None
    assert calls[0]["json"]["response_format"]["type"] == "json_schema"
    assert calls[1]["json"]["response_format"]["type"] == "json_object"


def test_json_object_fallback_carries_the_schema_in_the_prompt(settings: Settings, install_stub) -> None:
    calls = install_stub(
        StubResponse(400, {"error": {"message": "response_format json_schema unsupported"}}),
        chat_response(json.dumps(_valid_risk_payload())),
    )
    provider = OpenAIProvider(settings)
    provider.generate_structured(_request(), RiskAssessmentOutput)
    fallback_system = calls[1]["json"]["messages"][0]["content"]
    assert "JSON Schema" in fallback_system
    assert '"risk_level"' in fallback_system


def test_invalid_output_is_repaired_once(settings: Settings, install_stub) -> None:
    calls = install_stub(
        chat_response("{not json"),
        chat_response(json.dumps(_valid_risk_payload())),
    )
    provider = OpenAIProvider(settings)
    result = provider.generate_structured(_request(), RiskAssessmentOutput)
    assert result.structured is not None
    assert result.attempts == 2
    assert len(calls) == 2


def test_invalid_output_twice_fails_closed(settings: Settings, install_stub) -> None:
    install_stub(chat_response('{"risk_level": "NOPE"}'), chat_response("still wrong"))
    provider = OpenAIProvider(settings)
    with pytest.raises(AIResponseError) as excinfo:
        provider.generate_structured(_request(), RiskAssessmentOutput)
    assert "response_sha256" in excinfo.value.details


def test_empty_completion_is_failure_not_success(settings: Settings, install_stub) -> None:
    def truncated() -> StubResponse:
        return StubResponse(
            200,
            {
                "choices": [
                    {
                        "finish_reason": "length",
                        "message": {"role": "assistant", "content": "", "reasoning_content": "thinking..."},
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 10,
                    "completion_tokens_details": {"reasoning_tokens": 10},
                },
            },
        )

    # The provider retries once with a doubled budget, so two responses are needed.
    calls = install_stub(truncated(), truncated())
    provider = OpenAIProvider(settings)
    with pytest.raises(AIResponseError) as excinfo:
        provider.generate(_request())
    assert excinfo.value.details["finish_reason"] == "length"
    assert excinfo.value.details["reasoning_tokens"] == 10
    assert calls[1]["json"]["max_tokens"] == calls[0]["json"]["max_tokens"] * 2


def test_not_configured_raises_unavailable() -> None:
    provider = OpenAIProvider(Settings(ai_enabled=False, ai_api_key="sk-test"))
    assert provider.is_configured() is False
    with pytest.raises(AIUnavailableError):
        provider.generate(_request())


def test_cost_falls_back_to_gateway_list_cost(settings: Settings, install_stub) -> None:
    install_stub(
        chat_response(
            json.dumps(_valid_risk_payload()),
            usage={"prompt_tokens": 10, "completion_tokens": 5, "opencode": {"list_cost": 0.000033}},
        )
    )
    provider = OpenAIProvider(settings)
    result = provider.generate_structured(_request(), RiskAssessmentOutput)
    assert result.usage.cost_usd == pytest.approx(0.000033)


def test_strictify_requires_all_properties() -> None:
    schema = _strictify(
        {
            "type": "object",
            "properties": {"a": {"type": "string", "default": "x"}, "b": {"type": "integer"}},
            "required": [],
        }
    )
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["a", "b"]
    assert "default" not in schema["properties"]["a"]
