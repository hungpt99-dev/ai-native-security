"""Credential encryption and masking.

Repository access tokens are encrypted at rest with Fernet (AES-128-CBC +
HMAC). The key is derived from ``ANS_CREDENTIAL_KEY`` (or ``ANS_SECRET_KEY``
when unset) with HKDF-SHA256, so rotating the deployment secret re-derives the
key. Plaintext tokens never leave this module except to build an authenticated
git URL inside the worker process.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings
from app.core.errors import ValidationError

_TOKEN_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"sk-(?:live|test|proj)-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
)


@lru_cache
def _fernet() -> Fernet:
    settings = get_settings()
    material = settings.credential_key or settings.secret_key
    if not material:
        raise RuntimeError("Credential encryption key is not configured")
    # HKDF-like derivation with a fixed context, then urlsafe-b64 encode.
    derived = hashlib.sha256(b"ai-native-security/credential-key/v1" + material.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        raise ValidationError("Credential secret must not be empty")
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:  # pragma: no cover - configuration error path
        raise RuntimeError(
            "Unable to decrypt credential; ANS_CREDENTIAL_KEY/ANS_SECRET_KEY changed"
        ) from exc


def mask_secret(value: str | None, *, visible: int = 4) -> str:
    """Return a display-safe representation such as ``ghp_…3f9a``."""
    if not value:
        return ""
    if len(value) <= visible * 2:
        return "*" * len(value)
    return f"{value[:visible]}{'*' * 8}{value[-visible:]}"


def redact_text(text: str) -> str:
    """Remove token-shaped strings from free text before persisting it."""
    if not text:
        return text
    redacted = text
    for pattern in _TOKEN_PATTERNS:
        redacted = pattern.sub(lambda m: mask_secret(m.group(0)), redacted)
    # Generic key=value credentials in URLs (https://user:pass@host).
    return re.sub(r"(://[^/\s:@]+):([^/\s@]+)@", r"\1:***@", redacted)


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())
