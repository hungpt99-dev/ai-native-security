"""Scanner registry: resolves enabled adapters by name."""

from __future__ import annotations

from collections.abc import Iterable

from app.core.config import get_settings
from app.core.errors import NotFoundError
from app.modules.scanners.base import Scanner
from app.modules.scanners.gitleaks import GitleaksScanner
from app.modules.scanners.semgrep import SemgrepScanner
from app.modules.scanners.syft import SyftGenerator
from app.modules.scanners.trivy import TrivyScanner

_SCANNER_TYPES: dict[str, type[Scanner]] = {
    TrivyScanner.name: TrivyScanner,
    SemgrepScanner.name: SemgrepScanner,
    GitleaksScanner.name: GitleaksScanner,
}


def scanner_names() -> list[str]:
    return list(_SCANNER_TYPES)


def get_scanner(name: str) -> Scanner:
    scanner_type = _SCANNER_TYPES.get(name.lower())
    if scanner_type is None:
        raise NotFoundError("Unknown scanner", details={"scanner": name})
    return scanner_type()


def enabled_scanners() -> list[Scanner]:
    """Findings-producing scanners in the configured execution order."""
    configured: Iterable[str] = get_settings().scanners_enabled
    scanners: list[Scanner] = []
    for name in configured:
        scanner_type = _SCANNER_TYPES.get(name.lower())
        if scanner_type is not None:
            scanners.append(scanner_type())
    return scanners


def get_syft() -> SyftGenerator:
    return SyftGenerator()


def scanner_status() -> list[dict[str, object]]:
    """Availability probe used by the system status endpoint."""
    statuses: list[dict[str, object]] = []
    settings = get_settings()
    for name, scanner_type in _SCANNER_TYPES.items():
        scanner = scanner_type()
        availability = scanner.check_availability()
        statuses.append(
            {
                "scanner": name,
                "enabled": name in settings.scanners_enabled,
                **availability.as_dict(),
            }
        )
    syft = SyftGenerator()
    available, version, error = syft.check_availability()
    statuses.append(
        {
            "scanner": "syft",
            "enabled": "syft" in settings.scanners_enabled,
            "available": available,
            "version": version,
            "error": error,
        }
    )
    return statuses
