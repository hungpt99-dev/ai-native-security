"""CVSS parsing, repository URL validation and command-injection defences."""

from __future__ import annotations

import pytest

from app.core.errors import ValidationError
from app.core.validators import validate_branch_name, validate_repository_url
from app.modules.vulnerabilities.cvss import CvssParseError, cvss3_base_score, severity_from_score


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ],
)
def test_cvss3_base_score(vector: str, expected: float) -> None:
    assert cvss3_base_score(vector) == expected


def test_cvss_rejects_garbage() -> None:
    with pytest.raises(CvssParseError):
        cvss3_base_score("not-a-vector")
    with pytest.raises(CvssParseError):
        cvss3_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_severity_from_score() -> None:
    assert severity_from_score(None) == "UNKNOWN"
    assert severity_from_score(9.8) == "CRITICAL"
    assert severity_from_score(7.5) == "HIGH"
    assert severity_from_score(5.0) == "MEDIUM"
    assert severity_from_score(2.0) == "LOW"


def test_repository_url_is_normalized() -> None:
    reference = validate_repository_url("https://github.com/Example/Repo.git/")
    assert reference.url == "https://github.com/Example/Repo"
    assert reference.provider == "github"
    assert reference.name == "Repo"


def test_gitlab_subgroups_are_supported() -> None:
    reference = validate_repository_url("https://gitlab.com/group/subgroup/project")
    assert reference.provider == "gitlab"
    assert reference.owner == "group/subgroup"
    assert reference.name == "project"


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:org/repo.git",
        "ssh://git@github.com/org/repo.git",
        "file:///etc/passwd",
        "http://github.com/org/repo",
        "/local/path/repo",
        "https://evil.example.com/org/repo",
        "https://github.com/org/repo;rm -rf /",
        "https://user:token@github.com/org/repo",
        "https://127.0.0.1/org/repo",
        "",
        "https://github.com/org",
    ],
)
def test_invalid_repository_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        validate_repository_url(url)


def test_newline_injection_is_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_repository_url("https://github.com/org/repo\n--upload-pack=evil")


@pytest.mark.parametrize("branch", ["main", "release/1.2", "feature-x"])
def test_valid_branches(branch: str) -> None:
    assert validate_branch_name(branch) == branch


@pytest.mark.parametrize(
    "branch", ["--upload-pack=calc", "-x", "a..b", "main;rm -rf /", "$(id)", "a b", "/main"]
)
def test_invalid_branches(branch: str) -> None:
    with pytest.raises(ValidationError):
        validate_branch_name(branch)
