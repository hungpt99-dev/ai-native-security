"""NVD CVE API client and normalization.

The NVD feed is CVE-centric and rate limited (5 requests / 30s without an API
key, 50 / 30s with one). Pagination is explicit (``startIndex`` /
``resultsPerPage``) and incremental sync uses ``lastModStartDate``.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import get_settings
from app.core.enums import Severity, VulnerabilitySource
from app.core.logging import get_logger
from app.modules.vulnerabilities.http import HttpClient
from app.modules.vulnerabilities.records import (
    AffectedPackageRecord,
    ReferenceRecord,
    VulnerabilityRecord,
)

logger = get_logger(__name__)

MAX_WINDOW_DAYS = 120


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _nvd_format(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


class NvdClient:
    source = VulnerabilitySource.NVD.value

    def __init__(self, client: HttpClient | None = None) -> None:
        settings = get_settings()
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else None
        self.http = client or HttpClient(base_url=settings.nvd_api_url, headers=headers)
        self.results_per_page = settings.nvd_results_per_page
        self.delay = 0.7 if settings.nvd_api_key else settings.nvd_request_delay_seconds

    # ------------------------------------------------------------- queries
    def fetch_by_cve(self, cve_id: str) -> dict[str, Any] | None:
        response = self.http.get("", params={"cveId": cve_id.upper()})
        if not isinstance(response, dict):
            return None
        items = response.get("vulnerabilities") or []
        return items[0] if items else None

    def iter_recent(
        self,
        *,
        modified_since: datetime | None = None,
        modified_until: datetime | None = None,
        max_pages: int | None = None,
    ) -> Iterator[list[dict[str, Any]]]:
        """Yield pages of NVD entries for a modified-date window."""
        end = modified_until or datetime.now(UTC)
        start = modified_since or (end - timedelta(days=30))
        # NVD rejects windows longer than 120 days.
        if end - start > timedelta(days=MAX_WINDOW_DAYS):
            end = start + timedelta(days=MAX_WINDOW_DAYS)

        start_index = 0
        pages = 0
        while True:
            params = {
                "lastModStartDate": _nvd_format(start),
                "lastModEndDate": _nvd_format(end),
                "resultsPerPage": self.results_per_page,
                "startIndex": start_index,
            }
            response = self.http.get("", params=params)
            if not isinstance(response, dict):
                return
            items = response.get("vulnerabilities") or []
            if items:
                yield items
            pages += 1
            total = int(response.get("totalResults") or 0)
            start_index += len(items) or self.results_per_page
            if start_index >= total or not items:
                return
            if max_pages is not None and pages >= max_pages:
                return
            if self.delay:
                time.sleep(self.delay)


def parse_nvd_vulnerability(item: dict[str, Any]) -> VulnerabilityRecord | None:
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = (cve.get("id") or "").strip().upper()
    if not cve_id:
        return None

    summary = None
    description = None
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en":
            description = entry.get("value")
            summary = (description or "")[:1000]
            break

    score, vector, severity = _extract_metrics(cve)

    references = [
        ReferenceRecord(
            url=ref["url"],
            ref_type=(", ".join(ref.get("tags") or []))[:64] or None,
            source=VulnerabilitySource.NVD.value,
        )
        for ref in cve.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ]

    affected: dict[str, AffectedPackageRecord] = {}
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) > 5 and parts[0] == "cpe":
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 else "*"
                    record = affected.setdefault(
                        product,
                        AffectedPackageRecord(
                            ecosystem="CPE",
                            package_name=product,
                            purl=None,
                            affected_versions=[],
                            fixed_versions=[],
                            version_ranges=[],
                        ),
                    )
                    if version and version not in record.affected_versions:
                        record.affected_versions.append(version)

    weaknesses: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for entry in weakness.get("description") or []:
            value = entry.get("value")
            if value and value not in weaknesses:
                weaknesses.append(value)

    record = VulnerabilityRecord(
        source=VulnerabilitySource.NVD.value,
        source_id=cve_id,
        cve_id=cve_id,
        summary=summary,
        description=description,
        cvss_score=score,
        cvss_vector=vector,
        severity=severity,
        published_at=_parse_dt(cve.get("published")),
        modified_at=_parse_dt(cve.get("lastModified")),
        references=references,
        affected_packages=list(affected.values()),
    )
    if weaknesses:
        record.references.append(
            ReferenceRecord(
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}#vulnCwe",
                ref_type=("CWE: " + ", ".join(weaknesses[:5]))[:64],
                source=VulnerabilitySource.NVD.value,
            )
        )
    return record


def _extract_metrics(cve: dict[str, Any]) -> tuple[float | None, str | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            vector = data.get("vectorString")
            base_severity = data.get("baseSeverity") or entry.get("baseSeverity")
            if score is None:
                continue
            if base_severity:
                severity = str(base_severity).upper()
                if severity == "MODERATE":
                    severity = Severity.MEDIUM.value
            else:
                severity = _severity_from_score(float(score))
            return float(score), vector, severity
    return None, None, Severity.UNKNOWN.value


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return Severity.CRITICAL.value
    if score >= 7.0:
        return Severity.HIGH.value
    if score >= 4.0:
        return Severity.MEDIUM.value
    if score > 0:
        return Severity.LOW.value
    return Severity.INFO.value
