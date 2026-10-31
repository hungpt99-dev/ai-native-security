"""Scanner output parsing and finding normalization."""

from __future__ import annotations

import uuid
from pathlib import Path

from app.core.enums import Severity
from app.modules.scanners.gitleaks import GitleaksScanner
from app.modules.scanners.semgrep import SemgrepScanner
from app.modules.scanners.syft import ecosystem_from_purl
from app.modules.scanners.trivy import TrivyScanner

WORKSPACE = Path("/tmp/ws")


def test_trivy_parses_vulnerabilities() -> None:
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "requests",
                        "InstalledVersion": "2.19.0",
                        "FixedVersion": "2.32.0",
                        "Title": "Requests vulnerable to something",
                        "Description": "Long description",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 8.1}},
                        "PkgIdentifier": {"PURL": "pkg:pypi/requests@2.19.0"},
                        "References": ["https://example.com/advisory"],
                    }
                ],
            }
        ]
    }
    findings = TrivyScanner().parse_result(payload, WORKSPACE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CVE-2024-1234"
    assert finding.cve_id == "CVE-2024-1234"
    assert finding.severity == Severity.HIGH.value
    assert finding.package_name == "requests"
    assert finding.package_version == "2.19.0"
    assert finding.cvss_score == 8.1
    assert finding.metadata["fixed_version"] == "2.32.0"
    assert finding.category == "vulnerability"


def test_trivy_ignores_entries_without_ids() -> None:
    payload = {"Results": [{"Target": "x", "Vulnerabilities": [{"PkgName": "a"}]}]}
    assert TrivyScanner().parse_result(payload, WORKSPACE) == []


def test_trivy_handles_missing_cvss_and_unknown_severity() -> None:
    payload = {
        "Results": [
            {
                "Target": "go.sum",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "GHSA-xxxx-yyyy-zzzz",
                        "PkgName": "pkg",
                        "InstalledVersion": "1.0.0",
                        "Severity": "WHATEVER",
                    }
                ],
            }
        ]
    }
    finding = TrivyScanner().parse_result(payload, WORKSPACE)[0]
    assert finding.cvss_score is None
    assert finding.severity == Severity.UNKNOWN.value
    assert finding.cve_id is None


def test_semgrep_parses_and_redacts_credentials() -> None:
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.hardcoded-password",
                "path": str(WORKSPACE / "app/config.py"),
                "start": {"line": 12, "col": 1},
                "end": {"line": 12, "col": 40},
                "extra": {
                    "message": "Hardcoded password",
                    "severity": "ERROR",
                    "lines": 'password = "supersecretvalue"',
                    "metadata": {
                        "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                        "owasp": ["A07:2021"],
                        "category": "security",
                        "confidence": "HIGH",
                    },
                },
            }
        ]
    }
    findings = SemgrepScanner().parse_result(payload, WORKSPACE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH.value
    assert finding.file_path == "app/config.py"
    assert finding.line_number == 12
    assert "supersecretvalue" not in str(finding.metadata)
    assert finding.metadata["lines"] == "[redacted]"


def test_semgrep_missing_fields_are_tolerated() -> None:
    payload = {"results": [{"check_id": "x", "path": "a.py", "extra": {}}]}
    finding = SemgrepScanner().parse_result(payload, WORKSPACE)[0]
    assert finding.severity == Severity.MEDIUM.value
    assert finding.title == "x"


def test_gitleaks_masks_secret_values() -> None:
    payload = [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Token",
            "File": "deploy/env.sh",
            "StartLine": 4,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "Tags": ["aws", "key"],
            "Entropy": 3.5,
        }
    ]
    finding = GitleaksScanner().parse_result(payload, WORKSPACE)[0]
    assert finding.rule_id == "aws-access-token"
    assert finding.category == "secret"
    assert finding.severity in {Severity.HIGH.value, Severity.CRITICAL.value}
    masked = finding.metadata["secret_masked"]
    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.metadata["match_masked"]
    assert masked


def test_gitleaks_accepts_wrapped_payload() -> None:
    payload = {"findings": [{"RuleID": "generic-api-key", "File": "a.txt", "StartLine": 1}]}
    assert len(GitleaksScanner().parse_result(payload, WORKSPACE)) == 1


def test_gitleaks_empty_report() -> None:
    assert GitleaksScanner().parse_result([], WORKSPACE) == []


def test_fingerprint_is_stable_and_location_aware() -> None:
    asset_id = uuid.uuid4()
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1",
                        "PkgName": "requests",
                        "InstalledVersion": "2.19.0",
                        "Severity": "HIGH",
                    }
                ],
            }
        ]
    }
    first = TrivyScanner().parse_result(payload, WORKSPACE)[0]
    second = TrivyScanner().parse_result(payload, WORKSPACE)[0]
    assert first.compute_fingerprint(asset_id) == second.compute_fingerprint(asset_id)

    payload["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "2.20.0"
    upgraded = TrivyScanner().parse_result(payload, WORKSPACE)[0]
    assert upgraded.compute_fingerprint(asset_id) != first.fingerprint

    other_asset = uuid.uuid4()
    upgraded_fingerprint = upgraded.fingerprint
    assert first.compute_fingerprint(other_asset) != upgraded_fingerprint


def test_purl_ecosystem_mapping() -> None:
    assert ecosystem_from_purl("pkg:pypi/requests@2.0.0") == "PyPI"
    assert ecosystem_from_purl("pkg:npm/lodash@4.17.21") == "npm"
    assert ecosystem_from_purl("pkg:golang/github.com/x/y@v1.0.0") == "Go"
    assert ecosystem_from_purl(None, "library") == "library"
