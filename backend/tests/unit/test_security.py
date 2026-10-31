"""Credential handling, masking and authentication."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.errors import ValidationError
from app.core.security import decrypt_secret, encrypt_secret, mask_secret, redact_text
from app.core.storage import LocalFileStorage, validate_storage_key


def test_encryption_roundtrip() -> None:
    token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    ciphertext = encrypt_secret(token)
    assert token not in ciphertext
    assert decrypt_secret(ciphertext) == token


def test_encryption_is_randomized() -> None:
    token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    assert encrypt_secret(token) != encrypt_secret(token)


def test_masking() -> None:
    assert mask_secret("ghp_1234567890abcdef") == "ghp_********cdef"
    assert mask_secret("short") == "*****"
    assert mask_secret(None) == ""


def test_redaction_patterns() -> None:
    text = "token=ghp_1234567890abcdefghijklmnop and url https://user:pass@github.com/x"
    redacted = redact_text(text)
    assert "ghp_1234567890abcdefghijklmnop" not in redacted
    assert "user:pass@" not in redacted


def test_asset_token_is_never_returned(client: TestClient) -> None:
    token = "ghp_supersecrettokenvalue1234567890"
    response = client.post(
        "/api/v1/assets",
        json={
            "name": "private-repo",
            "repo_url": "https://github.com/example/private-repo",
            "access_token": token,
        },
    )
    assert response.status_code == 201, response.text
    body = response.text
    assert token not in body
    asset = response.json()
    assert asset["has_credential"] is True
    assert "credential_hint" in asset

    listing = client.get("/api/v1/assets")
    assert token not in listing.text


def test_auth_disabled_allows_anonymous(client: TestClient) -> None:
    assert client.get("/api/v1/assets").status_code == 200


def test_auth_enabled_rejects_missing_key(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_keys", ["test-key"])
    response = client.get("/api/v1/assets")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"

    wrong = client.get("/api/v1/assets", headers={"X-API-Key": "nope"})
    assert wrong.status_code == 401

    ok = client.get("/api/v1/assets", headers={"X-API-Key": "test-key"})
    assert ok.status_code == 200


def test_storage_rejects_path_traversal(tmp_path) -> None:
    storage = LocalFileStorage(tmp_path)
    for key in ["../escape.json", "/etc/passwd", "a/../../b", "..\\win"]:
        with pytest.raises(ValidationError):
            validate_storage_key(key)
        with pytest.raises(ValidationError):
            storage.put(key, b"x")


def test_storage_roundtrip(tmp_path) -> None:
    storage = LocalFileStorage(tmp_path)
    key = "sboms/asset/2026/01/01/file.json"
    storage.put(key, b'{"ok": true}')
    assert storage.exists(key)
    assert storage.get(key) == b'{"ok": true}'
    assert storage.size(key) == len(b'{"ok": true}')
    storage.delete(key)
    assert not storage.exists(key)
