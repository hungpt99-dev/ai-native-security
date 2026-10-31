"""Deterministic version comparison — the basis of remediation and verification."""

from __future__ import annotations

import pytest

from app.modules.security_intelligence.versions import (
    UncomparableVersion,
    compare_versions,
    is_affected,
    is_fixed_version_valid,
    minimum_fixed_version,
    parse_constraint,
    safe_compare,
    satisfies_constraints,
)


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0.0", "1.0.1", -1),
        ("1.0.1", "1.0.0", 1),
        ("1.2.3", "1.2.3", 0),
        ("v1.2.3", "1.2.3", 0),
        ("1.0", "1.0.0", 0),
        ("2.0", "10.0", -1),
        ("1.0.0-rc1", "1.0.0", -1),
        ("1.0.0-alpha", "1.0.0-beta", -1),
        ("1.0.0-alpha", "1.0.0-alpha.1", -1),
        ("1.0.0.dev1", "1.0.0a1", -1),
        ("1.0.0.post1", "1.0.0", 1),
        ("1.0.0+build5", "1.0.0", 0),
        ("1.0.0-1", "1.0.0", 1),
    ],
)
def test_generic_ordering(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.2.3-1", "1.2.3-2", -1),
        ("1.2.3-1ubuntu1", "1.2.3-1", 1),
        ("1:1.0-1", "2.0-1", 1),
        ("1.0~rc1", "1.0", -1),
        ("2.4.1-1+deb11u1", "2.4.1-1", 1),
    ],
)
def test_debian_ordering(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right, "Debian") == expected


def test_unparseable_is_unknown_not_equal() -> None:
    assert safe_compare("not-a-version", "1.0.0") is None
    assert safe_compare(None, "1.0.0") is None
    with pytest.raises(UncomparableVersion):
        compare_versions("", "1.0.0")


def test_osv_range_events() -> None:
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.6"}]}]
    assert is_affected("1.2.5", ranges, "npm") is True
    assert is_affected("1.2.6", ranges, "npm") is False
    assert is_affected("0.9.0", ranges, "npm") is True
    assert is_affected("2.0.0", ranges, "npm") is False


def test_osv_last_affected_and_limit() -> None:
    ranges = [{"events": [{"introduced": "1.0"}, {"last_affected": "1.4"}]}]
    assert is_affected("1.4", ranges) is True
    assert is_affected("1.5", ranges) is False
    limited = [{"events": [{"introduced": "1.0"}, {"limit": "1.9"}]}]
    assert is_affected("1.8", limited) is True
    assert is_affected("1.9", limited) is False


def test_ranges_absent_means_unknown() -> None:
    assert is_affected("1.0.0", None) is None
    assert is_affected("1.0.0", []) is None
    assert is_affected("weird", [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]) is None


def test_constraint_strings() -> None:
    constraints = parse_constraint(">=1.0.0, <1.2.5")
    assert constraints == [(">=", "1.0.0"), ("<", "1.2.5")]
    assert satisfies_constraints("1.2.0", constraints, "npm") is True
    assert satisfies_constraints("1.2.5", constraints, "npm") is False
    spaced = parse_constraint(">= 1.0 < 2.0")
    assert satisfies_constraints("1.5", spaced, None) is True


def test_minimum_fixed_version() -> None:
    assert minimum_fixed_version(["2.0.0", "1.2.6", "1.10.0"], "npm") == "1.2.6"
    assert minimum_fixed_version([], "npm") is None


def test_fixed_version_validation() -> None:
    fixed = ["1.2.6"]
    assert (
        is_fixed_version_valid("1.2.6", fixed_versions=fixed, current_version="1.2.0", ecosystem="npm")
        is True
    )
    assert (
        is_fixed_version_valid("1.3.0", fixed_versions=fixed, current_version="1.2.0", ecosystem="npm")
        is True
    )
    assert (
        is_fixed_version_valid("1.2.0", fixed_versions=fixed, current_version="1.2.0", ecosystem="npm")
        is False
    )
    assert (
        is_fixed_version_valid("latest", fixed_versions=fixed, current_version="1.2.0", ecosystem="npm")
        is None
    )
    assert (
        is_fixed_version_valid("9.9.9", fixed_versions=None, current_version="1.0", ecosystem="npm") is None
    )
