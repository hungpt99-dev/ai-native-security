"""Provider factory. The single place a concrete provider is constructed."""

from __future__ import annotations

import threading
from typing import Any

from app.core.config import Settings, get_settings
from app.modules.ai.errors import AIUnavailableError
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.providers.fake import FakeProvider
from app.modules.ai.providers.openai import OpenAIProvider

#: Provider ids accepted by ``ANS_AI_PROVIDER`` that mean "OpenAI-compatible".
_OPENAI_COMPATIBLE = {"openai", "openai-compatible", "azure-openai", "gateway"}

_lock = threading.Lock()
_cached: AIProvider | None = None
_cached_key: tuple[Any, ...] | None = None


def _key(settings: Settings) -> tuple[Any, ...]:
    return (
        settings.ai_provider.lower(),
        settings.ai_base_url,
        settings.ai_model,
        settings.ai_enabled,
        bool(settings.ai_api_key),
        tuple(sorted((settings.ai_extra_headers or {}).items())),
        settings.ai_requests_per_minute,
    )


def build_provider(settings: Settings | None = None) -> AIProvider:
    settings = settings or get_settings()
    kind = (settings.ai_provider or "").strip().lower()
    if kind == "fake":
        return FakeProvider()
    if kind in _OPENAI_COMPATIBLE:
        return OpenAIProvider(settings)
    raise AIUnavailableError("Unsupported AI provider", details={"provider": settings.ai_provider})


def get_provider() -> AIProvider:
    """Return the process-wide provider, rebuilt when configuration changes."""
    global _cached, _cached_key
    settings = get_settings()
    key = _key(settings)
    with _lock:
        if _cached is None or _cached_key != key:
            _cached = build_provider(settings)
            _cached_key = key
        return _cached


def set_provider(provider: AIProvider | None) -> None:
    """Test seam: install a specific provider (``None`` restores the default)."""
    global _cached, _cached_key
    with _lock:
        _cached = provider
        _cached_key = _key(get_settings()) if provider is None else None


def reset_provider() -> None:
    set_provider(None)


def provider_status() -> dict[str, Any]:
    """Safe description for ``/ai/health`` and ``/system/info`` — no secrets."""
    settings = get_settings()
    provider = get_provider()
    return {
        "enabled": settings.ai_enabled,
        "provider": provider.name,
        "model": settings.ai_model,
        "configured": provider.is_configured(),
        "base_url": settings.ai_base_url,
        "budget_usd_per_day": settings.ai_daily_budget_usd,
        "capabilities": provider.capabilities().model_dump(),
    }
