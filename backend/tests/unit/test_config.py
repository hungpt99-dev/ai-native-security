"""Configuration parsing from environment variables."""

from __future__ import annotations

import pytest

from app.core.config import Settings


def test_empty_list_variables_fall_back_to_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANS_API_KEYS", "")
    monkeypatch.setenv("ANS_ALLOWED_GIT_HOSTS", "")
    monkeypatch.setenv("ANS_SCANNERS_ENABLED", "")
    settings = Settings(_env_file=None)
    assert settings.api_keys == []
    assert settings.allowed_git_hosts == ["github.com", "gitlab.com"]
    assert settings.scanners_enabled == ["trivy", "semgrep", "gitleaks", "syft"]


def test_comma_separated_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANS_API_KEYS", "one,two")
    monkeypatch.setenv("ANS_ALLOWED_GIT_HOSTS", "github.com,gitlab.example.com")
    settings = Settings(_env_file=None)
    assert settings.api_keys == ["one", "two"]
    assert settings.allowed_git_hosts == ["github.com", "gitlab.example.com"]


def test_json_list_and_nested_env_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANS_API_KEYS", '["alpha", "beta"]')
    settings = Settings(_env_file=None)
    assert settings.api_keys == ["alpha", "beta"]


def test_credential_key_defaults_to_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANS_SECRET_KEY", "abc")
    monkeypatch.delenv("ANS_CREDENTIAL_KEY", raising=False)
    settings = Settings(_env_file=None)
    assert settings.credential_key is None
    assert settings.is_production is False
