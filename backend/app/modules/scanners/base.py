"""Common scanner interface and normalized finding model.

Every scanner adapter implements ``check_availability``, ``get_scanner_version``,
``build_command`` and ``parse_result``. ``run`` provides the shared execution
and error-handling flow so adapters only deal with tool specifics.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from app.core.config import get_settings
from app.core.enums import ScannerExecutionStatus, Severity
from app.core.logging import get_logger
from app.modules.scanners.execution import (
    ProcessResult,
    ScannerAvailability,
    binary_available,
    read_json_report,
    run_command,
)

logger = get_logger(__name__)

MAX_FINDINGS_PER_SCAN = 5000


@dataclass
class NormalizedFinding:
    scanner: str
    rule_id: str
    title: str
    category: str
    severity: str = Severity.UNKNOWN.value
    description: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    package_name: str | None = None
    package_version: str | None = None
    purl: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def compute_fingerprint(self, asset_id: uuid.UUID) -> str:
        """Stable identity used for deduplication across repeated scans.

        Scanner-generated ids are deliberately excluded: they change between
        runs. The identity is the semantic tuple (rule, location/package).
        """
        if self.package_name:
            parts = [
                str(asset_id),
                self.scanner,
                (self.rule_id or self.cve_id or "").lower(),
                "pkg",
                self.package_name.lower(),
                self.package_version or "",
            ]
        elif self.file_path:
            parts = [
                str(asset_id),
                self.scanner,
                (self.rule_id or "").lower(),
                "loc",
                self.file_path.lower(),
                str(self.line_number or 0),
            ]
        else:
            parts = [
                str(asset_id),
                self.scanner,
                (self.rule_id or self.title or "").lower(),
                "generic",
            ]
        digest = hashlib.sha256("|".join(parts).encode()).hexdigest()
        self.fingerprint = digest
        return digest


@dataclass
class ScannerRun:
    scanner: str
    status: str
    findings: list[NormalizedFinding]
    version: str | None = None
    exit_code: int | None = None
    duration_seconds: float = 0.0
    stdout_excerpt: str | None = None
    stderr_excerpt: str | None = None
    command: dict[str, Any] | None = None
    error_message: str | None = None


class Scanner(ABC):
    """Adapter contract for an external security tool."""

    name: ClassVar[str]
    category: ClassVar[str]

    def __init__(self) -> None:
        self.settings = get_settings()

    # ------------------------------------------------------------ interface
    @property
    @abstractmethod
    def binary(self) -> str:
        """Executable name or absolute path."""

    @abstractmethod
    def build_command(self, workspace: Path, report_path: Path) -> list[str]:
        """Return the argv vector used to run the tool."""

    @abstractmethod
    def parse_result(self, payload: Any, workspace: Path) -> list[NormalizedFinding]:
        """Convert the tool's native JSON output into normalized findings."""

    def version_command(self) -> list[str]:
        return [self.binary, "--version"]

    # -------------------------------------------------------------- helpers
    def version_from_output(self, output: str) -> str | None:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in lines:
            if line.lower().startswith("version:"):
                return line.split(":", 1)[1].strip()[:64]
        return lines[0][:64] if lines else None

    def get_scanner_version(self) -> str | None:
        if not binary_available(self.binary):
            return None
        result = run_command(
            self.version_command(),
            cwd=Path("/tmp"),  # noqa: S108 - neutral cwd for version probes
            timeout=30,
            extra_env=None,
        )
        combined = f"{result.stdout}\n{result.stderr}"
        return self.version_from_output(combined) if result.exit_code == 0 else None

    def check_availability(self) -> ScannerAvailability:
        if not binary_available(self.binary):
            return ScannerAvailability(
                available=False,
                error=f"{self.binary} is not installed or not on PATH",
            )
        try:
            version = self.get_scanner_version()
        except Exception as exc:  # pragma: no cover - defensive
            return ScannerAvailability(available=False, error=str(exc))
        return ScannerAvailability(available=True, version=version)

    def run_with_timeout(self, command: list[str], workspace: Path, report_path: Path) -> ProcessResult:
        return run_command(
            command,
            cwd=workspace,
            timeout=self.settings.scanner_timeout_seconds,
        )

    # ----------------------------------------------------------------- flow
    def run(self, workspace: Path, report_dir: Path) -> ScannerRun:
        availability = self.check_availability()
        if not availability.available:
            return ScannerRun(
                scanner=self.name,
                status=ScannerExecutionStatus.SKIPPED.value,
                findings=[],
                error_message=availability.error,
            )

        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"{self.name}.json"
        command = self.build_command(workspace, report_path)
        result = self.run_with_timeout(command, workspace, report_path)

        if result.timed_out:
            return ScannerRun(
                scanner=self.name,
                status=ScannerExecutionStatus.TIMED_OUT.value,
                findings=[],
                version=availability.version,
                exit_code=result.exit_code,
                duration_seconds=result.duration_seconds,
                stdout_excerpt=result.stdout_excerpt,
                stderr_excerpt=result.stderr_excerpt,
                command={"argv": command},
                error_message="Scanner timed out",
            )

        # Most scanners exit non-zero when findings exist; a parseable report
        # is the authoritative success signal.
        try:
            payload = read_json_report(report_path)
        except json.JSONDecodeError as exc:
            return ScannerRun(
                scanner=self.name,
                status=ScannerExecutionStatus.FAILED.value,
                findings=[],
                version=availability.version,
                exit_code=result.exit_code,
                duration_seconds=result.duration_seconds,
                stdout_excerpt=result.stdout_excerpt,
                stderr_excerpt=result.stderr_excerpt,
                command={"argv": command},
                error_message=f"Invalid JSON report: {exc}",
            )

        if payload is None:
            if result.exit_code != 0:
                return ScannerRun(
                    scanner=self.name,
                    status=ScannerExecutionStatus.FAILED.value,
                    findings=[],
                    version=availability.version,
                    exit_code=result.exit_code,
                    duration_seconds=result.duration_seconds,
                    stdout_excerpt=result.stdout_excerpt,
                    stderr_excerpt=result.stderr_excerpt,
                    command={"argv": command},
                    error_message=f"Scanner exited with code {result.exit_code} and produced no report",
                )
            payload = [] if self.name == "gitleaks" else {}

        try:
            findings = self.parse_result(payload, workspace)
        except Exception as exc:
            logger.exception("failed to parse %s output", self.name)
            return ScannerRun(
                scanner=self.name,
                status=ScannerExecutionStatus.FAILED.value,
                findings=[],
                version=availability.version,
                exit_code=result.exit_code,
                duration_seconds=result.duration_seconds,
                stdout_excerpt=result.stdout_excerpt,
                stderr_excerpt=result.stderr_excerpt,
                command={"argv": command},
                error_message=f"Failed to parse scanner output: {exc}",
            )

        truncated = findings[:MAX_FINDINGS_PER_SCAN]
        error_message = _report_errors(payload)
        return ScannerRun(
            scanner=self.name,
            status=ScannerExecutionStatus.SUCCESS.value,
            findings=truncated,
            version=availability.version,
            exit_code=result.exit_code,
            duration_seconds=result.duration_seconds,
            stdout_excerpt=result.stdout_excerpt,
            stderr_excerpt=result.stderr_excerpt,
            command={"argv": command},
            error_message=error_message,
        )


def _report_errors(payload: Any) -> str | None:
    """Surface tool-level errors embedded in an otherwise successful report."""
    if not isinstance(payload, dict):
        return None
    errors = payload.get("errors")
    if not errors:
        return None
    first = json.dumps(errors[0], default=str) if errors else ""
    return f"{len(errors)} tool error(s) reported: {first[:500]}"


def normalize_severity(value: str | None, *, default: str = Severity.UNKNOWN.value) -> str:
    if not value:
        return default
    key = value.strip().upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL.value,
        "HIGH": Severity.HIGH.value,
        "IMPORTANT": Severity.HIGH.value,
        "ERROR": Severity.HIGH.value,
        "MEDIUM": Severity.MEDIUM.value,
        "MODERATE": Severity.MEDIUM.value,
        "WARNING": Severity.MEDIUM.value,
        "LOW": Severity.LOW.value,
        "MINOR": Severity.LOW.value,
        "INFO": Severity.INFO.value,
        "INFORMATIONAL": Severity.INFO.value,
        "NEGLIGIBLE": Severity.INFO.value,
        "UNKNOWN": Severity.UNKNOWN.value,
        "NONE": Severity.INFO.value,
    }
    return mapping.get(key, default)


def relative_path(raw: str | None, workspace: Path) -> str | None:
    """Store repository-relative paths; never leak the worker's temp path."""
    if not raw:
        return None
    candidate = Path(raw)
    try:
        if candidate.is_absolute():
            return str(candidate.resolve().relative_to(workspace.resolve()))
    except (ValueError, OSError):
        return candidate.name
    return raw


def utcnow() -> datetime:
    return datetime.now(UTC)
