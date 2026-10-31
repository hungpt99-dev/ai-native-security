"""Normalized vulnerability records shared by all intelligence sources."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime


@dataclass
class ReferenceRecord:
    url: str
    ref_type: str | None = None
    source: str | None = None


@dataclass
class AffectedPackageRecord:
    ecosystem: str = ""
    package_name: str = ""
    purl: str | None = None
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    version_ranges: list[dict[str, object]] = field(default_factory=list)


@dataclass
class VulnerabilityRecord:
    source: str
    source_id: str
    cve_id: str | None = None
    osv_id: str | None = None
    summary: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str = "UNKNOWN"
    published_at: datetime | None = None
    modified_at: datetime | None = None
    is_kev: bool = False
    kev_due_date: date | None = None
    kev_required_action: str | None = None
    references: list[ReferenceRecord] = field(default_factory=list)
    affected_packages: list[AffectedPackageRecord] = field(default_factory=list)

    def natural_key(self) -> tuple[str, str]:
        return (self.source, self.source_id)
