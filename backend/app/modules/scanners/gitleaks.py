"""Gitleaks adapter: hardcoded secrets detection.

The scanner is invoked with ``--redact`` so the report itself contains masked
secrets; this layer additionally masks anything that still looks like a token.
Discovered secret values are never persisted or returned by the API.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.enums import Severity
from app.core.security import mask_secret, redact_text
from app.modules.scanners.base import NormalizedFinding, Scanner, relative_path

_HIGH_IMPACT_RULES = (
    "private-key",
    "aws",
    "gcp",
    "azure",
    "github-pat",
    "gitlab-pat",
    "slack",
    "stripe",
    "generic-api-key",
    "jwt",
    "password",
)


class GitleaksScanner(Scanner):
    name = "gitleaks"
    category = "secret"

    @property
    def binary(self) -> str:
        return self.settings.gitleaks_binary

    def version_command(self) -> list[str]:
        return [self.binary, "version"]

    def build_command(self, workspace: Path, report_path: Path) -> list[str]:
        return [
            self.binary,
            "detect",
            "--source",
            str(workspace),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--no-banner",
            "--redact",
            "--no-git",
            "--exit-code",
            "0",
        ]

    def parse_result(self, payload: Any, workspace: Path) -> list[NormalizedFinding]:
        if isinstance(payload, dict):  # tolerate {"findings": [...]} wrappers
            payload = payload.get("findings") or payload.get("Results") or []
        if not isinstance(payload, list):
            return []

        findings: list[NormalizedFinding] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            rule_id = (item.get("RuleID") or "gitleaks.unknown").strip()
            description = (item.get("Description") or rule_id).strip()
            match = redact_text(str(item.get("Match") or ""))
            tags = [str(tag) for tag in (item.get("Tags") or [])]
            findings.append(
                NormalizedFinding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=description[:500],
                    description=(
                        f"Potential secret detected by rule '{rule_id}'. "
                        "The value is masked and intentionally not stored."
                    ),
                    category=self.category,
                    severity=self._severity(rule_id, tags),
                    file_path=relative_path(item.get("File"), workspace),
                    line_number=item.get("StartLine"),
                    metadata={
                        "rule_tags": tags,
                        "entropy": item.get("Entropy"),
                        "secret_masked": mask_secret(str(item.get("Secret") or "")),
                        "match_masked": match[:200],
                        "commit": item.get("Commit"),
                        "author": item.get("Author"),
                        "date": item.get("Date"),
                        "symlink_file": item.get("SymlinkFile"),
                    },
                )
            )
        return findings

    @staticmethod
    def _severity(rule_id: str, tags: list[str]) -> str:
        haystack = f"{rule_id} {' '.join(tags)}".lower()
        if any(rule in haystack for rule in _HIGH_IMPACT_RULES):
            return Severity.CRITICAL.value if "private-key" in haystack else Severity.HIGH.value
        return Severity.MEDIUM.value
