"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from app.core.config import get_settings
from app.core.enums import Severity, VulnerabilitySource
from app.modules.vulnerabilities.http import HttpClient
from app.modules.vulnerabilities.records import (
    AffectedPackageRecord,
    VulnerabilityRecord,
)


class KevClient:
    source = VulnerabilitySource.CISA_KEV.value

    def __init__(self, client: HttpClient | None = None) -> None:
        settings = get_settings()
        self.url = settings.kev_catalog_url
        self.http = client or HttpClient()

    def fetch_catalog(self) -> dict[str, Any]:
        response = self.http.get(self.url)
        return response if isinstance(response, dict) else {}

    def entries(self) -> list[VulnerabilityRecord]:
        catalog = self.fetch_catalog()
        records: list[VulnerabilityRecord] = []
        for entry in catalog.get("vulnerabilities") or []:
            record = parse_kev_entry(entry)
            if record is not None:
                records.append(record)
        return records


def parse_kev_entry(entry: dict[str, Any]) -> VulnerabilityRecord | None:
    cve_id = (entry.get("cveID") or "").strip().upper()
    if not cve_id:
        return None
    due_date: date | None = None
    raw_due = entry.get("dueDate")
    if raw_due:
        try:
            due_date = date.fromisoformat(str(raw_due))
        except ValueError:
            due_date = None
    published: datetime | None = None
    raw_added = entry.get("dateAdded")
    if raw_added:
        try:
            published = datetime.fromisoformat(str(raw_added)).replace(tzinfo=UTC)
        except ValueError:
            published = None

    vendor = entry.get("vendorProject") or ""
    product = entry.get("product") or ""
    name = entry.get("vulnerabilityName") or cve_id
    record = VulnerabilityRecord(
        source=VulnerabilitySource.CISA_KEV.value,
        source_id=cve_id,
        cve_id=cve_id,
        summary=f"{name}"[:1000],
        description=entry.get("shortDescription"),
        severity=Severity.HIGH.value,
        published_at=published,
        modified_at=published,
        is_kev=True,
        kev_due_date=due_date,
        kev_required_action=entry.get("requiredAction"),
    )
    if vendor or product:
        record.affected_packages.append(
            AffectedPackageRecord(
                ecosystem="",
                package_name=f"{vendor} {product}".strip(),
                affected_versions=[],
                fixed_versions=[],
                version_ranges=[],
            )
        )
    return record
