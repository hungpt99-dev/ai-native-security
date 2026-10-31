"""Structured logging configuration.

Emits JSON log lines in non-development environments (and in development when
``ANS_LOG_JSON=true``) including request/scan correlation identifiers. Secrets
are never passed to the logger by application code; the formatter additionally
filters obvious credential keys from structured extras.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
scan_id_var: ContextVar[str | None] = ContextVar("scan_id", default=None)

_SENSITIVE_KEYS = {
    "token",
    "access_token",
    "password",
    "secret",
    "authorization",
    "api_key",
    "credential",
    "encrypted_secret",
    "private_key",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: A003 - stdlib API
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        scan_id = scan_id_var.get()
        if scan_id:
            payload["scan_id"] = scan_id
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = "***" if key.lower() in _SENSITIVE_KEYS else value
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: A003 - stdlib API
        stamp = datetime.now(UTC).isoformat()
        base = f"{stamp} {record.levelname:<8} {record.name:<32} {record.getMessage()}"
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if json_logs else ConsoleFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    # Third-party noise control.
    for noisy in ("httpx", "httpcore", "urllib3", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, root.level))
    logging.getLogger("uvicorn.error").setLevel(level.upper())


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def log_with_fields(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    logger.log(level, message, extra={"extra_fields": fields})
