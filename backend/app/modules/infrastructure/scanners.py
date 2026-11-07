"""Infrastructure scanner adapters (Trivy config/image, Checkov).

Adapters are pure functions around a command line and a JSON report: no
database, no FastAPI. They run through the hardened subprocess layer (argv only,
rlimits, process-group kill on timeout, sanitized environment) that already
serves the repository scanners.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.enums import InfraScanner, Severity
from app.modules.scanners.base import NormalizedFinding, normalize_severity
from app.modules.scanners.execution import ProcessResult, read_json_report, run_command


@dataclass
class InfraAvailability:
    available: bool
    version: str | None
    error: str | None


class InfraAdapter(ABC):
    name: str
    target_kind: str
    category: str
    binary_setting: str

    @property
    def binary(self) -> str:
        return str(getattr(get_settings(), self.binary_setting))

    def check_availability(self) -> InfraAvailability:
        path = shutil.which(self.binary)
        if path is None:
            return InfraAvailability(False, None, f"{self.binary} is not installed")
        return InfraAvailability(True, None, None)

    def build_command(self, target: str, report_path: Path) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def run(self, target: str, report_path: Path, *, cwd: Path) -> ProcessResult:
        settings = get_settings()
        return run_command(
            self.build_command(target, report_path),
            cwd=cwd,
            timeout=settings.infrastructure_timeout_seconds,
        )

    def read(self, report_path: Path) -> Any:
        return read_json_report(report_path)

    @abstractmethod
    def parse_result(self, payload: Any, *, target: str) -> list[NormalizedFinding]: ...

    def accepts_exit_code(self, code: int) -> bool:
        """Trivy returns 0 with findings; Checkov returns 1 when checks fail."""
        return code in {0, 1}


class TrivyConfigAdapter(InfraAdapter):
    name = InfraScanner.TRIVY_CONFIG.value
    target_kind = "IAC_REPOSITORY"
    category = "misconfiguration"
    binary_setting = "trivy_binary"

    def build_command(self, target: str, report_path: Path) -> list[str]:
        settings = get_settings()
        return [
            self.binary,
            "config",
            "--quiet",
            "--format",
            "json",
            "--output",
            str(report_path),
            "--timeout",
            f"{max(60, settings.infrastructure_timeout_seconds - 30)}s",
            "--skip-dirs",
            ".git",
            "--skip-dirs",
            "node_modules",
            "--cache-dir",
            "/tmp/ans-trivy-cache",  # noqa: S108 - container-local cache
            str(target),
        ]

    def parse_result(self, payload: Any, *, target: str) -> list[NormalizedFinding]:
        if not isinstance(payload, dict):
            return []
        findings: list[NormalizedFinding] = []
        for result in payload.get("Results") or []:
            if not isinstance(result, dict):
                continue
            file_path = str(result.get("Target") or target)[:1000]
            for item in result.get("Misconfigurations") or []:
                rule_id = str(item.get("ID") or item.get("AVDID") or "").strip()
                if not rule_id:
                    continue
                cause = item.get("CauseMetadata") or {}
                line = cause.get("StartLine") if isinstance(cause, dict) else None
                findings.append(
                    NormalizedFinding(
                        scanner=self.name,
                        rule_id=rule_id,
                        title=(item.get("Title") or rule_id)[:500],
                        description=(item.get("Description") or item.get("Message") or None),
                        category=self.category,
                        severity=normalize_severity(item.get("Severity"), default=Severity.UNKNOWN.value),
                        file_path=file_path,
                        line_number=int(line) if isinstance(line, int) else None,
                        metadata={
                            "message": (item.get("Message") or "")[:2000],
                            "resolution": (item.get("Resolution") or "")[:2000],
                            "references": [str(ref)[:500] for ref in (item.get("References") or [])[:5]],
                            "check_type": result.get("Type"),
                            "target": file_path,
                        },
                    )
                )
        return findings


class CheckovAdapter(InfraAdapter):
    name = InfraScanner.CHECKOV.value
    target_kind = "IAC_REPOSITORY"
    category = "misconfiguration"
    binary_setting = "checkov_binary"

    def build_command(self, target: str, report_path: Path) -> list[str]:
        return [
            self.binary,
            "-d",
            str(target),
            "-o",
            "json",
            "--output-file-path",
            str(report_path.parent),
            "--quiet",
            "--compact",
            "--skip-download",
        ]

    def read(self, report_path: Path) -> Any:
        # Checkov writes results_<timestamp>.json into the output directory when
        # --output-file-path is a directory; read the newest file there.
        if report_path.is_file():
            return read_json_report(report_path)
        directory = report_path.parent
        candidates = sorted(directory.glob("results_*.json"), key=lambda p: p.stat().st_mtime)
        if not candidates:
            return read_json_report(report_path)
        return read_json_report(candidates[-1])

    def parse_result(self, payload: Any, *, target: str) -> list[NormalizedFinding]:
        if isinstance(payload, list):  # checkov emits a list when several frameworks run
            documents = [item for item in payload if isinstance(item, dict)]
        elif isinstance(payload, dict):
            documents = [payload]
        else:
            return []
        findings: list[NormalizedFinding] = []
        for document in documents:
            if not isinstance(document, dict):
                continue
            raw_results = document.get("results")
            results: dict[str, Any] = raw_results if isinstance(raw_results, dict) else {}
            for item in results.get("failed_checks") or []:
                rule_id = str(item.get("check_id") or "").strip()
                if not rule_id:
                    continue
                line_range = item.get("file_line_range") or []
                line = line_range[0] if line_range and isinstance(line_range[0], int) else None
                findings.append(
                    NormalizedFinding(
                        scanner=self.name,
                        rule_id=rule_id,
                        title=(item.get("check_name") or rule_id)[:500],
                        description=(item.get("guideline") or item.get("check_name") or None),
                        category=self.category,
                        severity=normalize_severity(item.get("severity"), default=Severity.UNKNOWN.value),
                        file_path=str(item.get("file_path") or target)[:1000],
                        line_number=line,
                        metadata={
                            "resource": str(item.get("resource") or "")[:500],
                            "check_class": item.get("check_class"),
                            "guideline": (item.get("guideline") or "")[:1000],
                            "framework": document.get("check_type"),
                        },
                    )
                )
        return findings


class TrivyImageAdapter(InfraAdapter):
    name = InfraScanner.TRIVY_IMAGE.value
    target_kind = "CONTAINER_IMAGE"
    category = "container_vulnerability"
    binary_setting = "trivy_binary"

    def build_command(self, target: str, report_path: Path) -> list[str]:
        settings = get_settings()
        return [
            self.binary,
            "image",
            "--quiet",
            "--format",
            "json",
            "--output",
            str(report_path),
            "--scanners",
            "vuln",
            "--timeout",
            f"{max(60, settings.infrastructure_timeout_seconds - 30)}s",
            "--cache-dir",
            "/tmp/ans-trivy-cache",  # noqa: S108 - container-local cache
            "--image-src",
            "remote",
            str(target),
        ]

    def parse_result(self, payload: Any, *, target: str) -> list[NormalizedFinding]:
        if not isinstance(payload, dict):
            return []
        findings: list[NormalizedFinding] = []
        for result in payload.get("Results") or []:
            if not isinstance(result, dict):
                continue
            for vuln in result.get("Vulnerabilities") or []:
                vuln_id = str(vuln.get("VulnerabilityID") or "").strip()
                if not vuln_id:
                    continue
                findings.append(
                    NormalizedFinding(
                        scanner=self.name,
                        rule_id=vuln_id,
                        title=(vuln.get("Title") or f"{vuln_id} in {vuln.get('PkgName')}")[:500],
                        description=(vuln.get("Description") or None),
                        category=self.category,
                        severity=normalize_severity(vuln.get("Severity"), default=Severity.UNKNOWN.value),
                        file_path=None,
                        package_name=(vuln.get("PkgName") or None),
                        package_version=(vuln.get("InstalledVersion") or None),
                        purl=((vuln.get("PkgIdentifier") or {}).get("PURL")),
                        cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                        metadata={
                            "fixed_version": (vuln.get("FixedVersion") or "")[:200],
                            "target": str(result.get("Target") or target)[:500],
                            "class": result.get("Class"),
                        },
                    )
                )
        return findings


_ADAPTERS: dict[str, type[InfraAdapter]] = {
    TrivyConfigAdapter.name: TrivyConfigAdapter,
    CheckovAdapter.name: CheckovAdapter,
    TrivyImageAdapter.name: TrivyImageAdapter,
}


def get_adapter(name: str) -> InfraAdapter:
    adapter_type = _ADAPTERS.get(name)
    if adapter_type is None:
        raise KeyError(name)
    return adapter_type()


def adapters_for(target_kind: str) -> list[str]:
    return [name for name, cls in _ADAPTERS.items() if cls.target_kind == target_kind]


def availability() -> list[dict[str, Any]]:
    rows = []
    for name, adapter_type in _ADAPTERS.items():
        adapter = adapter_type()
        status = adapter.check_availability()
        rows.append(
            {
                "scanner": name,
                "target_kind": adapter.target_kind,
                "available": status.available,
                "error": status.error,
            }
        )
    return rows
