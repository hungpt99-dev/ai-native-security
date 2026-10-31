"""Syft adapter: SBOM generation and package extraction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from app.core.config import get_settings
from app.core.enums import SbomFormat
from app.core.errors import ExternalServiceError
from app.core.logging import get_logger
from app.modules.scanners.execution import binary_available, run_command

logger = get_logger(__name__)

FORMAT_ARGUMENTS: dict[str, str] = {
    SbomFormat.CYCLONEDX_JSON.value: "cyclonedx-json",
    SbomFormat.SPDX_JSON.value: "spdx-json",
}

#: PURL type -> OSV ecosystem name.
PURL_ECOSYSTEMS: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "maven": "Maven",
    "gem": "RubyGems",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "composer": "Packagist",
    "swift": "SwiftURL",
    "pub": "Pub",
    "hex": "Hex",
    "deb": "Debian",
    "rpm": "RPM",
    "apk": "Alpine",
    "github": "GitHub Actions",
    "alpm": "Arch Linux",
    "cocoapods": "CocoaPods",
    "conda": "conda",
}


@dataclass
class SbomPackageInfo:
    name: str
    version: str
    ecosystem: str | None = None
    purl: str | None = None
    license: str | None = None
    source_type: str | None = None
    cpe: str | None = None


@dataclass
class SbomDocument:
    content: bytes
    format: str
    spec_version: str | None
    tool_version: str | None
    packages: list[SbomPackageInfo]


def ecosystem_from_purl(purl: str | None, fallback: str | None = None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return fallback
    purl_type = purl[4:].split("/", 1)[0].split("@", 1)[0].lower()
    return PURL_ECOSYSTEMS.get(purl_type, fallback or purl_type)


class SyftGenerator:
    """Generates SBOMs with Syft and parses them into package records."""

    name: ClassVar[str] = "syft"

    def __init__(self) -> None:
        self.settings = get_settings()

    @property
    def binary(self) -> str:
        return self.settings.syft_binary

    def check_availability(self) -> tuple[bool, str | None, str | None]:
        if not binary_available(self.binary):
            return False, None, f"{self.binary} is not installed or not on PATH"
        result = run_command(
            [self.binary, "version"],
            cwd=Path("/tmp"),  # noqa: S108 - neutral cwd for version probes
            timeout=30,
        )
        version = None
        if result.exit_code == 0:
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            # Prefer the explicit "Version: x.y.z" line over the "Application:" banner.
            for line in lines:
                if line.lower().startswith("version:"):
                    version = line.split(":", 1)[1].strip()[:64]
                    break
            if version is None and lines:
                version = lines[0][:64]
        return True, version, None

    def get_scanner_version(self) -> str | None:
        return self.check_availability()[1]

    def generate(
        self,
        workspace: Path,
        output_dir: Path,
        *,
        sbom_format: str = SbomFormat.CYCLONEDX_JSON.value,
    ) -> SbomDocument:
        available, version, error = self.check_availability()
        if not available:
            raise ExternalServiceError(error or "Syft is unavailable")

        fmt = sbom_format.upper()
        if fmt not in FORMAT_ARGUMENTS:
            raise ExternalServiceError(f"Unsupported SBOM format: {sbom_format}")
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"sbom.{FORMAT_ARGUMENTS[fmt]}"

        command = [
            self.binary,
            "scan",
            f"dir:{workspace}",
            "-q",
            "-o",
            f"{FORMAT_ARGUMENTS[fmt]}={report_path}",
        ]
        result = run_command(
            command, cwd=workspace, timeout=self.settings.scanner_timeout_seconds
        )
        if result.timed_out:
            raise ExternalServiceError("Syft timed out while generating the SBOM")
        if not report_path.is_file():
            raise ExternalServiceError(
                "Syft produced no SBOM",
                details={"exit_code": result.exit_code, "stderr": result.stderr_excerpt},
            )

        raw = report_path.read_bytes()
        payload = json.loads(raw)
        packages, spec_version = self.parse_result(payload, fmt)
        return SbomDocument(
            content=raw,
            format=fmt,
            spec_version=spec_version,
            tool_version=version,
            packages=packages,
        )

    # ------------------------------------------------------------- parsing
    def parse_result(self, payload: Any, sbom_format: str) -> tuple[list[SbomPackageInfo], str | None]:
        if not isinstance(payload, dict):
            return [], None
        if sbom_format == SbomFormat.SPDX_JSON.value:
            return _parse_spdx(payload)
        return _parse_cyclonedx(payload)


def _parse_cyclonedx(payload: dict[str, Any]) -> tuple[list[SbomPackageInfo], str | None]:
    spec_version = payload.get("specVersion")
    packages: list[SbomPackageInfo] = []
    seen: set[tuple[str, str, str | None]] = set()
    for component in payload.get("components") or []:
        if not isinstance(component, dict):
            continue
        name = (component.get("name") or "").strip()
        if not name or name.startswith("/"):
            # Syft emits filesystem entries as "file" components with absolute
            # paths; they are not packages and must not enter the inventory.
            continue
        component_type = str(component.get("type") or "").lower()
        if component_type == "file":
            continue
        version = str(component.get("version") or "").strip()
        purl = component.get("purl")
        if not version and not purl:
            continue
        licenses = component.get("licenses") or []
        license_names: list[str] = []
        for entry in licenses:
            if isinstance(entry, dict):
                license_obj = entry.get("license") or {}
                value = license_obj.get("id") or license_obj.get("name")
                if value:
                    license_names.append(value)
            elif isinstance(entry, str):
                license_names.append(entry)
        cpes = component.get("cpe") or (component.get("purl") and None)
        key = (name.lower(), version, purl)
        if key in seen:
            continue
        seen.add(key)
        packages.append(
            SbomPackageInfo(
                name=name,
                version=version,
                ecosystem=ecosystem_from_purl(purl),
                purl=purl,
                license=", ".join(sorted(set(license_names))) or None,
                source_type=component.get("type"),
                cpe=cpes if isinstance(cpes, str) else None,
            )
        )
    return packages, str(spec_version) if spec_version else None


def _parse_spdx(payload: dict[str, Any]) -> tuple[list[SbomPackageInfo], str | None]:
    spec_version = payload.get("spdxVersion")
    packages: list[SbomPackageInfo] = []
    seen: set[tuple[str, str]] = set()
    for package in payload.get("packages") or []:
        if not isinstance(package, dict):
            continue
        name = (package.get("name") or "").strip()
        if not name or name.startswith("/"):
            continue
        version = str(package.get("versionInfo") or "").strip()
        if (name.lower(), version) in seen:
            continue
        seen.add((name.lower(), version))
        refs = package.get("externalRefs") or []
        purl = None
        for ref in refs:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        packages.append(
            SbomPackageInfo(
                name=name,
                version=version,
                ecosystem=ecosystem_from_purl(purl),
                purl=purl,
                license=package.get("licenseDeclared") or package.get("licenseConcluded"),
                source_type="library",
                cpe=None,
            )
        )
    return packages, str(spec_version) if spec_version else None
