"""Semgrep adapter: static application security testing (SAST)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.core.enums import Severity
from app.modules.scanners.base import (
    NormalizedFinding,
    Scanner,
    normalize_severity,
    relative_path,
)

_SEVERITY_FROM_METADATA = {
    "critical": Severity.CRITICAL.value,
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.INFO.value,
}

#: Lines that look like a credential assignment are redacted in metadata so a
#: SAST finding can never echo a secret to the dashboard.
_CREDENTIAL_LINE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]"
)


class SemgrepScanner(Scanner):
    name = "semgrep"
    category = "sast"

    @property
    def binary(self) -> str:
        return self.settings.semgrep_binary

    def version_command(self) -> list[str]:
        return [self.binary, "--version"]

    def build_command(self, workspace: Path, report_path: Path) -> list[str]:
        config = self.settings.semgrep_config
        if not config:
            config = "p/security-audit"
        return [
            self.binary,
            "scan",
            "--json",
            "--output",
            str(report_path),
            "--config",
            config,
            "--metrics",
            "off",
            "-j",
            str(max(1, self.settings.semgrep_jobs)),
            "--quiet",
            "--disable-version-check",
            "--max-target-bytes",
            "2000000",
            "--timeout",
            "60",
            "--timeout-threshold",
            "3",
            str(workspace),
        ]

    def parse_result(self, payload: Any, workspace: Path) -> list[NormalizedFinding]:
        if not isinstance(payload, dict):
            return []
        findings: list[NormalizedFinding] = []
        for item in payload.get("results") or []:
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            check_id = item.get("check_id") or "semgrep.unknown"
            start = item.get("start") or {}
            lines = extra.get("lines") or ""
            if _CREDENTIAL_LINE.search(lines or ""):
                lines = "[redacted]"

            severity = normalize_severity(extra.get("severity"), default=Severity.MEDIUM.value)
            meta_severity = str(metadata.get("impact") or metadata.get("severity") or "").lower()
            if meta_severity in _SEVERITY_FROM_METADATA:
                severity = _SEVERITY_FROM_METADATA[meta_severity]

            findings.append(
                NormalizedFinding(
                    scanner=self.name,
                    rule_id=check_id,
                    title=(metadata.get("shortDescription") or check_id)[:500],
                    description=(extra.get("message") or "").strip() or None,
                    category=self._category(metadata),
                    severity=severity,
                    file_path=relative_path(item.get("path"), workspace),
                    line_number=start.get("line"),
                    metadata={
                        "cwe": metadata.get("cwe") or [],
                        "owasp": metadata.get("owasp") or [],
                        "references": metadata.get("references") or [],
                        "confidence": metadata.get("confidence"),
                        "lines": (lines or "")[:1000],
                        "end_line": (item.get("end") or {}).get("line"),
                    },
                )
            )
        return findings

    @staticmethod
    def _category(metadata: dict[str, Any]) -> str:
        raw = str(metadata.get("category") or "").lower()
        if "security" in raw:
            return "sast"
        return raw or "sast"
