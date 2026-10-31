"""Shared HTTP client with rate limiting and retries.

All vulnerability feeds are fetched through this client so retry/backoff and
rate-limit behaviour is consistent and testable.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.errors import ExternalServiceError
from app.core.logging import get_logger

logger = get_logger(__name__)

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class HttpClient:
    def __init__(
        self,
        *,
        base_url: str = "",
        timeout: float | None = None,
        max_retries: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        settings = get_settings()
        self.base_url = base_url
        self.timeout = timeout or settings.http_timeout_seconds
        self.max_retries = max_retries if max_retries is not None else settings.http_max_retries
        self.headers = {"User-Agent": "ai-native-security/0.1 (+self-hosted)"}
        if headers:
            self.headers.update(headers)

    def request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any] | list[Any]:
        target = f"{self.base_url}{url}" if self.base_url and not url.startswith("http") else url
        last_error: str | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(
                    timeout=self.timeout, headers=self.headers, follow_redirects=True
                ) as client:
                    response = client.request(method, target, **kwargs)
                if response.status_code in RETRYABLE_STATUS:
                    delay = self._retry_delay(response, attempt)
                    last_error = f"HTTP {response.status_code}"
                    logger.warning(
                        "retryable response from upstream",
                        extra={
                            "extra_fields": {
                                "url": target,
                                "status": response.status_code,
                                "attempt": attempt,
                                "delay_seconds": delay,
                            }
                        },
                    )
                    time.sleep(delay)
                    continue
                if response.status_code == 404:
                    raise ExternalServiceError("Upstream resource not found", details={"url": target})
                if response.status_code >= 400:
                    raise ExternalServiceError(
                        f"Upstream error {response.status_code}",
                        details={"url": target, "body": response.text[:300]},
                    )
                if not response.content:
                    return {}
                return response.json()
            except (httpx.HTTPError, ValueError) as exc:
                last_error = str(exc)
                if attempt >= self.max_retries:
                    break
                delay = min(60, 2**attempt)
                logger.warning(
                    "http request failed, retrying",
                    extra={"extra_fields": {"url": target, "attempt": attempt, "error": last_error}},
                )
                time.sleep(delay)
        raise ExternalServiceError(
            "Upstream request failed after retries",
            details={"url": target, "error": last_error},
        )

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(120.0, float(retry_after))
            except ValueError:
                pass
        return min(60.0, 2.0**attempt)

    def get(self, url: str, **kwargs: Any) -> dict[str, Any] | list[Any]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> dict[str, Any] | list[Any]:
        return self.request("POST", url, **kwargs)
