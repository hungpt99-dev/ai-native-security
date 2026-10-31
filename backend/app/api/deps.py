"""Authentication and authorization dependencies.

Phase 1 ships static API-key authentication (constant-time comparison) that is
disabled for local development and can be enabled with ``ANS_AUTH_ENABLED=true``
plus ``ANS_API_KEYS``. The ``Principal`` shape leaves room for OIDC/RBAC later
without changing route signatures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header

from app.core.config import get_settings
from app.core.errors import AuthenticationError
from app.core.security import constant_time_equals


@dataclass(frozen=True)
class Principal:
    subject: str
    is_authenticated: bool


ANONYMOUS = Principal(subject="anonymous", is_authenticated=False)


def get_principal(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    settings = get_settings()
    if not settings.auth_enabled:
        return ANONYMOUS
    if not x_api_key:
        raise AuthenticationError("Missing X-API-Key header")
    for index, key in enumerate(settings.api_keys):
        if key and constant_time_equals(key, x_api_key):
            return Principal(subject=f"api-key-{index + 1}", is_authenticated=True)
    raise AuthenticationError("Invalid API key")


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
