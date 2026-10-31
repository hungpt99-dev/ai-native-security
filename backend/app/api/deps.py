"""Authentication and authorization dependencies.

Phase 1 ships static API-key authentication (constant-time comparison) that is
disabled for local development and can be enabled with ``ANS_AUTH_ENABLED=true``
plus ``ANS_API_KEYS``. The ``Principal`` shape leaves room for OIDC/RBAC later
without changing route signatures.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header

from app.core.config import Settings, get_settings
from app.core.errors import AuthenticationError
from app.core.logging import get_logger
from app.core.security import constant_time_equals

logger = get_logger(__name__)


@dataclass(frozen=True)
class Principal:
    subject: str
    is_authenticated: bool
    #: ``None`` means "all assets"; a set restricts reads to those assets.
    asset_scope: frozenset[uuid.UUID] | None = None


ANONYMOUS = Principal(subject="anonymous", is_authenticated=False)


def asset_scope_for(index: int, settings: Settings) -> frozenset[uuid.UUID] | None:
    """Resolve the asset scope configured for the ``index``-th API key (1-based)."""
    raw = (settings.api_key_scopes or {}).get(str(index))
    if raw is None:
        return None
    scoped: set[uuid.UUID] = set()
    for value in raw:
        try:
            scoped.add(uuid.UUID(str(value)))
        except (ValueError, AttributeError):
            logger.warning(
                "ignoring invalid asset id in api key scope",
                extra={"extra_fields": {"key_index": index}},
            )
    return frozenset(scoped)


def get_principal(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    settings = get_settings()
    if not settings.auth_enabled:
        return ANONYMOUS
    if not x_api_key:
        raise AuthenticationError("Missing X-API-Key header")
    for index, key in enumerate(settings.api_keys, start=1):
        if key and constant_time_equals(key, x_api_key):
            return Principal(
                subject=f"api-key-{index}",
                is_authenticated=True,
                asset_scope=asset_scope_for(index, settings),
            )
    raise AuthenticationError("Invalid API key")


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
