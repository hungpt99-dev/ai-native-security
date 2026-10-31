"""EPSS (Exploit Prediction Scoring System) ingestion.

EPSS is a daily probability that a CVE is exploited in the next 30 days. It is a
first-class *deterministic* signal: it is fetched from FIRST, stored per CVE and
never guessed by a model.

The feed is a gzipped CSV (``cve,epss,percentile``) with a leading comment line
carrying the model version and score date. Rows are written with a bulk
``INSERT ... ON CONFLICT DO UPDATE`` so a refresh is idempotent.
"""

from __future__ import annotations

import csv
import gzip
import io
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ExternalServiceError
from app.core.logging import get_logger
from app.modules.vulnerabilities.models import VulnerabilityEpss

logger = get_logger(__name__)

EPSS_SOURCE = "EPSS"
BATCH_SIZE = 5000
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class EpssClient:
    """Downloads and parses the FIRST EPSS feed."""

    def __init__(self, url: str | None = None, *, timeout: float | None = None) -> None:
        settings = get_settings()
        self.url = url or settings.epss_url
        self.timeout = timeout or max(settings.http_timeout_seconds, 120.0)
        self.max_retries = settings.http_max_retries

    def fetch(self) -> tuple[list[dict[str, Any]], dict[str, str]]:
        last_error: str | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                    response = client.get(
                        self.url, headers={"User-Agent": "ai-native-security/1.0 (+self-hosted)"}
                    )
                if response.status_code in RETRYABLE_STATUS:
                    delay = min(60.0, 2.0**attempt)
                    last_error = f"HTTP {response.status_code}"
                    logger.warning(
                        "retryable EPSS response",
                        extra={
                            "extra_fields": {
                                "status": response.status_code,
                                "attempt": attempt,
                                "delay_seconds": delay,
                            }
                        },
                    )
                    time.sleep(delay)
                    continue
                if response.status_code >= 400:
                    raise ExternalServiceError(
                        f"EPSS feed error {response.status_code}",
                        details={"url": self.url},
                    )
                raw = response.content
                if raw[:2] == b"\x1f\x8b":
                    raw = gzip.decompress(raw)
                return parse_epss_csv(raw)
            except (httpx.HTTPError, OSError, ValueError) as exc:
                last_error = str(exc)
                if attempt >= self.max_retries:
                    break
                time.sleep(min(60.0, 2.0**attempt))
        raise ExternalServiceError(
            "EPSS feed could not be downloaded", details={"url": self.url, "error": last_error}
        )


def parse_epss_csv(raw: bytes) -> tuple[list[dict[str, Any]], dict[str, str]]:
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    meta: dict[str, str] = {}
    start = 0
    for index, line in enumerate(lines[:5]):
        if line.startswith("#"):
            for part in line.lstrip("#").split(","):
                if ":" in part:
                    key, value = part.split(":", 1)
                    meta[key.strip()] = value.strip()
            start = index + 1
            continue
        start = index
        break
    rows: list[dict[str, Any]] = []
    scored = _parse_date(meta.get("score_date"))
    model_version = meta.get("model_version")
    reader = csv.DictReader(io.StringIO("\n".join(lines[start:])))
    for entry in reader:
        cve = (entry.get("cve") or entry.get("cve_id") or "").strip()
        if not cve.upper().startswith("CVE-"):
            continue
        try:
            score = float(entry.get("epss") or 0)
            percentile = float(entry.get("percentile") or 0)
        except (TypeError, ValueError):
            continue
        rows.append(
            {
                "cve_id": cve.upper(),
                "score": round(score, 4),
                "percentile": round(percentile, 4),
                "model_version": model_version,
                "scored_date": scored,
            }
        )
    return rows, meta


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def iter_batches(rows: list[dict[str, Any]], size: int = BATCH_SIZE) -> Iterator[list[dict[str, Any]]]:
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


def upsert_scores(db: Session, rows: list[dict[str, Any]]) -> int:
    """Bulk upsert; returns the number of rows written."""
    written = 0
    for batch in iter_batches(rows):
        payload = [{**row, "id": uuid.uuid4()} for row in batch]
        statement = insert(VulnerabilityEpss).values(payload)
        statement = statement.on_conflict_do_update(
            index_elements=[VulnerabilityEpss.cve_id],
            set_={
                "score": statement.excluded.score,
                "percentile": statement.excluded.percentile,
                "model_version": statement.excluded.model_version,
                "scored_date": statement.excluded.scored_date,
                "updated_at": datetime.now(UTC),
            },
        )
        db.execute(statement)
        db.commit()
        written += len(batch)
    return written


def scores_for(db: Session, cve_ids: list[str] | set[str]) -> dict[str, dict[str, Any]]:
    """Look up EPSS scores for a set of CVEs (empty dict when unknown)."""
    wanted = [cve.upper() for cve in cve_ids if cve]
    if not wanted:
        return {}
    rows = db.execute(
        select(
            VulnerabilityEpss.cve_id,
            VulnerabilityEpss.score,
            VulnerabilityEpss.percentile,
            VulnerabilityEpss.scored_date,
            VulnerabilityEpss.model_version,
        ).where(VulnerabilityEpss.cve_id.in_(wanted))
    ).all()
    return {
        cve_id: {
            "score": float(score),
            "percentile": float(percentile),
            "scored_date": scored_date.isoformat() if scored_date else None,
            "model_version": model_version,
        }
        for cve_id, score, percentile, scored_date, model_version in rows
    }


def latest_score_date(db: Session) -> date | None:
    return db.execute(
        select(VulnerabilityEpss.scored_date)
        .order_by(VulnerabilityEpss.scored_date.desc())
        .limit(1)
    ).scalar_one_or_none()
