"""Trivy adapter: OS package, dependency and filesystem vulnerabilities."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.enums import Severity
from app.modules.scanners.base import (
    NormalizedFinding,
    Scanner,
    normalize_severity,
    relative_path,
)


class TrivyScanner(Scanner):
    name = "trivy"
    category = "vulnerability"

    @property
    def binary(self) -> str:
        return self.settings.trivy_binary

    def version_command(self) -> list[str]:
        return [self.binary, "--version"]

    def build_command(self, workspace: Path, report_path: Path) -> list[str]:
        return [
            self.binary,
            "fs",
            "--quiet",
            "--format",
            "json",
            "--output",
            str(report_path),
            "--scanners",
            "vuln",
            "--skip-dirs",
            ".git",
            "--skip-dirs",
            "node_modules",
            "--timeout",
            f"{max(60, self.settings.scanner_timeout_seconds - 30)}s",
            "--cache-dir",
            "/tmp/ans-trivy-cache",  # noqa: S108 - container-local, non-sensitive cache
            str(workspace),
        ]

    def parse_result(self, payload: Any, workspace: Path) -> list[NormalizedFinding]:
        if not isinstance(payload, dict):
            return []
        findings: list[NormalizedFinding] = []
        for result in payload.get("Results") or []:
            target = result.get("Target") or ""
            for vuln in result.get("Vulnerabilities") or []:
                vuln_id = (vuln.get("VulnerabilityID") or "").strip()
                if not vuln_id:
                    continue
                pkg_name = (vuln.get("PkgName") or "").strip()
                installed = (vuln.get("InstalledVersion") or "").strip() or None
                pkg_identifier = vuln.get("PkgIdentifier") or {}
                purl = pkg_identifier.get("PURL")
                cvss = _extract_cvss(vuln)
                severity = normalize_severity(
                    vuln.get("Severity"),
                    default=Severity.UNKNOWN.value,
                )
                findings.append(
                    NormalizedFinding(
                        scanner=self.name,
                        rule_id=vuln_id,
                        title=(vuln.get("Title") or f"{vuln_id} in {pkg_name}").strip()[:500],
                        description=(vuln.get("Description") or "").strip() or None,
                        category=self.category,
                        severity=severity,
                        file_path=relative_path(target, workspace) if target else None,
                        package_name=pkg_name or None,
                        package_version=installed,
                        purl=purl,
                        cve_id=vuln_id if vuln_id.upper().startswith("CVE-") else None,
                        cvss_score=cvss,
                        metadata={
                            "fixed_version": vuln.get("FixedVersion"),
                            "primary_url": vuln.get("PrimaryURL"),
                            "references": (vuln.get("References") or [])[:20],
                            "cwe_ids": vuln.get("CweIDs") or [],
                            "target": target,
                            "class": result.get("Class"),
                            "type": result.get("Type"),
                            "status": vuln.get("Status"),
                            "data_source": (vuln.get("DataSource") or {}).get("Name"),
                        },
                    )
                )
        return findings


def _extract_cvss(vuln: dict[str, Any]) -> float | None:
    """Prefer NVD v3 score, then any available vendor score."""
    cvss = vuln.get("CVSS") or {}
    for key in ("nvd", "redhat", "ghsa", "bitnami"):
        entry = cvss.get(key) or {}
        for score_key in ("V3Score", "V2Score"):
            score = entry.get(score_key)
            if isinstance(score, (int, float)):
                return round(float(score), 1)
    return None
