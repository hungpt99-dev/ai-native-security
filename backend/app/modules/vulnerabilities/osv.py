"""OSV API client and normalization.

OSV is queried per package (``/v1/querybatch``) and hydrated by id
(``/v1/vulns/{id}``). Not every OSV entry has a CVE alias and not every entry
has a CVSS vector, so both fields stay optional.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from app.core.config import get_settings
from app.core.enums import Severity, VulnerabilitySource
from app.core.logging import get_logger
from app.modules.vulnerabilities.cvss import (
    CvssParseError,
    cvss3_base_score,
    severity_from_score,
)
from app.modules.vulnerabilities.http import HttpClient
from app.modules.vulnerabilities.records import (
    AffectedPackageRecord,
    ReferenceRecord,
    VulnerabilityRecord,
)

logger = get_logger(__name__)

_MAX_BATCH = 500

#: Ecosystems accepted by the OSV API. Values outside this set cause HTTP 400,
#: so they are filtered before querying (SBOM ecosystems are not always OSV
#: ecosystem names).
OSV_ECOSYSTEMS: frozenset[str] = frozenset(
    {
        "Alpine",
        "AlmaLinux",
        "Bitnami",
        "Chainguard",
        "CRAN",
        "crates.io",
        "Debian",
        "GitHub Actions",
        "Go",
        "Hackage",
        "Hex",
        "Linux",
        "Mageia",
        "Maven",
        "npm",
        "NuGet",
        "openSUSE",
        "OSS-Fuzz",
        "Packagist",
        "Pub",
        "PyPI",
        "Red Hat",
        "Rocky Linux",
        "RubyGems",
        "SwiftURL",
        "Ubuntu",
        "Wolfi",
    }
)


def is_supported_ecosystem(ecosystem: str | None) -> bool:
    if not ecosystem:
        return False
    base = ecosystem.split(":", 1)[0]
    return ecosystem in OSV_ECOSYSTEMS or base in OSV_ECOSYSTEMS


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class OsvClient:
    source = VulnerabilitySource.OSV.value

    def __init__(self, client: HttpClient | None = None) -> None:
        settings = get_settings()
        self.http = client or HttpClient(base_url=settings.osv_api_url)

    # ------------------------------------------------------------- queries
    def query(self, ecosystem: str, name: str, version: str | None) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name}}
        if version:
            payload["version"] = version
        response = self.http.post("/v1/query", json=payload)
        if not isinstance(response, dict):
            return []
        return response.get("vulns") or []

    def query_batch(
        self, packages: Sequence[tuple[str, str, str | None]]
    ) -> list[list[dict[str, Any]]]:
        """Query many packages, tolerating individual rejected entries.

        A single invalid ecosystem makes the whole OSV batch fail with HTTP
        400, so a failed chunk is split until the offending query is isolated.
        """
        results: list[list[dict[str, Any]]] = []
        for start in range(0, len(packages), _MAX_BATCH):
            chunk = list(packages[start : start + _MAX_BATCH])
            results.extend(self._query_chunk(chunk))
        return results

    def _query_chunk(self, chunk: list[tuple[str, str, str | None]]) -> list[list[dict[str, Any]]]:
        if not chunk:
            return []
        queries = []
        for ecosystem, name, version in chunk:
            query: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name}}
            if version:
                query["version"] = version
            queries.append(query)
        try:
            response = self.http.post("/v1/querybatch", json={"queries": queries})
        except Exception as exc:
            if len(chunk) == 1:
                logger.warning(
                    "OSV rejected a package query",
                    extra={"extra_fields": {"package": chunk[0][1], "error": str(exc)[:200]}},
                )
                return [[]]
            midpoint = len(chunk) // 2
            logger.warning(
                "OSV batch rejected; splitting chunk",
                extra={"extra_fields": {"size": len(chunk), "error": str(exc)[:200]}},
            )
            return self._query_chunk(chunk[:midpoint]) + self._query_chunk(chunk[midpoint:])

        batch_results = (response or {}).get("results", []) if isinstance(response, dict) else []
        rows = [(entry or {}).get("vulns") or [] for entry in batch_results]
        while len(rows) < len(chunk):
            rows.append([])
        return rows

    def fetch(self, osv_id: str) -> dict[str, Any]:
        response = self.http.get(f"/v1/vulns/{osv_id}")
        return response if isinstance(response, dict) else {}

    def hydrate(self, summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return full records, fetching details when only ids are present."""
        full: list[dict[str, Any]] = []
        for entry in summaries:
            if entry.get("affected") and (entry.get("id") or ""):
                full.append(entry)
                continue
            osv_id = entry.get("id")
            if not osv_id:
                continue
            try:
                full.append(self.fetch(osv_id))
            except Exception:  # pragma: no cover - single record failure is tolerable
                logger.warning("failed to fetch OSV record %s", osv_id)
        return full


def parse_osv_vulnerability(payload: dict[str, Any]) -> VulnerabilityRecord | None:
    osv_id = (payload.get("id") or "").strip()
    if not osv_id:
        return None

    aliases = [str(alias).upper() for alias in payload.get("aliases") or []]
    cve_candidates = [a for a in aliases if a.startswith("CVE-")]
    cve_id = cve_candidates[0] if cve_candidates else (
        osv_id if osv_id.upper().startswith("CVE-") else None
    )

    cvss_vector, cvss_score, severity = _extract_severity(payload)
    references = [
        ReferenceRecord(url=ref["url"], ref_type=ref.get("type"), source=VulnerabilitySource.OSV.value)
        for ref in payload.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ]
    affected: list[AffectedPackageRecord] = []
    for entry in payload.get("affected") or []:
        package = entry.get("package") or {}
        name = package.get("name") or ""
        if not name:
            continue
        ecosystem = package.get("ecosystem") or ""
        ranges: list[dict[str, object]] = []
        fixed_versions: list[str] = []
        for range_entry in entry.get("ranges") or []:
            events = range_entry.get("events") or []
            ranges.append({"type": range_entry.get("type"), "events": events})
            for event in events:
                fixed = event.get("fixed")
                if fixed and fixed not in fixed_versions:
                    fixed_versions.append(fixed)
        affected.append(
            AffectedPackageRecord(
                ecosystem=ecosystem,
                package_name=name,
                purl=package.get("purl"),
                affected_versions=[str(v) for v in entry.get("versions") or []],
                fixed_versions=fixed_versions,
                version_ranges=ranges,
            )
        )

    return VulnerabilityRecord(
        source=VulnerabilitySource.OSV.value,
        source_id=osv_id,
        cve_id=cve_id,
        osv_id=osv_id,
        summary=(payload.get("summary") or "")[:1000] or None,
        description=payload.get("details"),
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity,
        published_at=_parse_dt(payload.get("published")),
        modified_at=_parse_dt(payload.get("modified")),
        references=references,
        affected_packages=affected,
    )


def _extract_severity(payload: dict[str, Any]) -> tuple[str | None, float | None, str]:
    database_severity = str((payload.get("database_specific") or {}).get("severity") or "").upper()
    for entry in payload.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        vector = entry.get("score") or ""
        if entry.get("type", "").upper().startswith("CVSS_V3") and vector:
            try:
                score = cvss3_base_score(vector)
            except CvssParseError:
                continue
            return vector, score, severity_from_score(score)
        if entry.get("type", "").upper() == "CVSS_V4":
            # v4 scoring is not implemented; keep the vector, infer severity
            # from the source's own classification when present.
            severity = _map_source_severity(database_severity)
            return vector, None, severity
    severity = _map_source_severity(database_severity)
    return None, None, severity


def _map_source_severity(value: str) -> str:
    mapping = {
        "CRITICAL": Severity.CRITICAL.value,
        "HIGH": Severity.HIGH.value,
        "MODERATE": Severity.MEDIUM.value,
        "MEDIUM": Severity.MEDIUM.value,
        "LOW": Severity.LOW.value,
    }
    return mapping.get(value, Severity.UNKNOWN.value)
