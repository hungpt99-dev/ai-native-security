"""Provider abstraction.

Business modules never import a concrete provider: they depend on this interface
through ``ai.providers.registry.get_provider()``. The interface is synchronous
because the whole application is (sync SQLAlchemy, sync worker, sync FastAPI
handlers in a threadpool); async companions exist for future callers and simply
delegate to the sync path in a worker thread, so there is exactly one code path.
"""

from __future__ import annotations

import asyncio
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, TypeVar

from pydantic import BaseModel

from app.modules.ai.errors import AIRateLimitedError, AIUnavailableError
from app.modules.ai.schemas.provider import AIRequest, AIResult, ProviderCapabilities

SchemaT = TypeVar("SchemaT", bound=BaseModel)


class RateLimiter:
    """Thread-safe sliding-window limiter (requests per minute).

    One process holds one limiter. That is sufficient here: the API and the
    worker are separate processes and each gets its own budget, which is the
    conservative direction.
    """

    def __init__(self, requests_per_minute: int) -> None:
        self.limit = max(1, requests_per_minute)
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self, *, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                while self._events and now - self._events[0] >= 60.0:
                    self._events.popleft()
                if len(self._events) < self.limit:
                    self._events.append(now)
                    return
                wait_for = 60.0 - (now - self._events[0])
            if time.monotonic() + wait_for > deadline:
                raise AIRateLimitedError(
                    "Local rate limit exceeded",
                    details={"requests_per_minute": self.limit},
                )
            time.sleep(max(0.05, min(wait_for, 5.0)))


class AIProvider(ABC):
    """The only surface business code is allowed to depend on."""

    name: str = "base"

    @abstractmethod
    def capabilities(self) -> ProviderCapabilities: ...

    @abstractmethod
    def is_configured(self) -> bool:
        """True when the provider can be called (credentials present)."""

    @abstractmethod
    def generate(self, request: AIRequest) -> AIResult:
        """Free-text generation."""

    @abstractmethod
    def generate_structured(self, request: AIRequest, schema: type[SchemaT]) -> AIResult:
        """Generation constrained to ``schema``; result carries ``structured``."""

    async def agenerate(self, request: AIRequest) -> AIResult:
        return await asyncio.to_thread(self.generate, request)

    async def agenerate_structured(self, request: AIRequest, schema: type[SchemaT]) -> AIResult:
        return await asyncio.to_thread(self.generate_structured, request, schema)

    # ----------------------------------------------------------------- helpers
    def ensure_available(self) -> None:
        if not self.is_configured():
            raise AIUnavailableError(
                "AI provider is not configured",
                details={"provider": self.name},
            )

    def describe(self) -> dict[str, Any]:
        capabilities = self.capabilities()
        return {
            "name": self.name,
            "configured": self.is_configured(),
            "capabilities": capabilities.model_dump(),
        }
