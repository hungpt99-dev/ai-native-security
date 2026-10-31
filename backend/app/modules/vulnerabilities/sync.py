"""Scheduled synchronization of vulnerability intelligence sources.

Each sync is recorded in ``vulnerability_sync_history`` with counts, cursor and
errors. Pages are committed incrementally so a long NVD window does not hold a
single transaction open.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import VulnerabilitySource
from app.core.logging import get_logger
from app.modules.sbom.models import SbomPackage
from app.modules.vulnerabilities import repository as vuln_repo
from app.modules.vulnerabilities.kev import KevClient
from app.modules.vulnerabilities.models import Vulnerability
from app.modules.vulnerabilities.nvd import NvdClient, parse_nvd_vulnerability
from app.modules.vulnerabilities.osv import OsvClient, parse_osv_vulnerability

logger = get_logger(__name__)

MAX_OSV_PACKAGES = 1000
MAX_OSV_HYDRATIONS = 300


def _finish(
    db: Session,
    history,
    *,
    status: str,
    processed: int = 0,
    created: int = 0,
    updated: int = 0,
    error: str | None = None,
    cursor: str | None = None,
) -> None:
    finished = datetime.now(UTC)
    history.status = status
    history.finished_at = finished
    history.duration_seconds = int((finished - history.started_at).total_seconds())
    history.records_processed = processed
    history.records_created = created
    history.records_updated = updated
    history.error_message = error[:4000] if error else None
    history.cursor = cursor
    db.commit()


def sync_kev(db: Session) -> dict[str, Any]:
    """Full catalog refresh; small (~1.2k entries) and fast."""
    source = VulnerabilitySource.CISA_KEV.value
    history = vuln_repo.start_sync(db, source)
    db.commit()
    started = time.perf_counter()
    try:
        records = KevClient().entries()
        created, updated, _ = vuln_repo.bulk_upsert(db, records)
        due_dates = {
            record.cve_id: record.kev_due_date
            for record in records
            if record.cve_id and record.kev_due_date
        }
        flagged = vuln_repo.apply_kev_flags(db, due_dates.keys(), due_dates=due_dates)
        db.commit()
        _finish(
            db,
            history,
            status="SUCCESS",
            processed=len(records),
            created=created,
            updated=updated,
        )
        logger.info(
            "kev sync completed",
            extra={
                "extra_fields": {
                    "entries": len(records),
                    "created": created,
                    "updated": updated,
                    "flagged_existing": flagged,
                    "duration_seconds": round(time.perf_counter() - started, 2),
                }
            },
        )
        return {
            "source": source,
            "status": "SUCCESS",
            "processed": len(records),
            "created": created,
            "updated": updated,
            "flagged_existing": flagged,
        }
    except Exception as exc:
        db.rollback()
        history = db.get(type(history), history.id)
        if history is not None:
            _finish(db, history, status="FAILED", error=str(exc))
        logger.exception("kev sync failed")
        raise


def sync_nvd(db: Session, *, lookback_days: int | None = None) -> dict[str, Any]:
    """Incremental NVD sync over a modified-date window."""
    settings = get_settings()
    source = VulnerabilitySource.NVD.value
    history = vuln_repo.start_sync(db, source)
    db.commit()

    last = vuln_repo.last_successful_sync(db, source)
    end = datetime.now(UTC)
    if last and last.finished_at:
        start = last.finished_at - timedelta(days=1)  # overlap guards clock skew
    else:
        start = end - timedelta(days=lookback_days or settings.nvd_initial_lookback_days)

    processed = created = updated = 0
    pages = 0
    try:
        client = NvdClient()
        for page in client.iter_recent(
            modified_since=start,
            modified_until=end,
            max_pages=settings.nvd_max_pages_per_sync,
        ):
            records = [
                record
                for item in page
                if (record := parse_nvd_vulnerability(item)) is not None
            ]
            page_created, page_updated, _ = vuln_repo.bulk_upsert(db, records)
            processed += len(records)
            created += page_created
            updated += page_updated
            pages += 1
            # Expose progress while a long window is still streaming.
            history.records_processed = processed
            history.records_created = created
            history.records_updated = updated
            db.commit()
        status = "SUCCESS"
    except Exception as exc:
        db.rollback()
        history = db.get(type(history), history.id)
        if history is not None:
            _finish(db, history, status="FAILED", error=str(exc))
        logger.exception("nvd sync failed")
        raise

    _finish(
        db,
        history,
        status=status,
        processed=processed,
        created=created,
        updated=updated,
        cursor=start.isoformat(),
    )
    logger.info(
        "nvd sync completed",
        extra={
            "extra_fields": {
                "pages": pages,
                "processed": processed,
                "created": created,
                "updated": updated,
            }
        },
    )
    return {
        "source": source,
        "status": status,
        "processed": processed,
        "created": created,
        "updated": updated,
        "pages": pages,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
    }


def inventory_packages(db: Session, limit: int = MAX_OSV_PACKAGES) -> list[tuple[str, str, str]]:
    """Distinct packages from stored SBOMs, used for scheduled OSV refresh."""
    rows = db.execute(
        select(SbomPackage.ecosystem, SbomPackage.name, SbomPackage.version)
        .where(SbomPackage.ecosystem.is_not(None))
        .where(SbomPackage.version != "")
        .distinct()
        .limit(limit)
    ).all()
    return [(eco or "", name, version) for eco, name, version in rows if eco and name]


def sync_osv(db: Session) -> dict[str, Any]:
    """Refresh OSV data for packages we have already inventoried."""
    source = VulnerabilitySource.OSV.value
    history = vuln_repo.start_sync(db, source)
    db.commit()

    packages = inventory_packages(db)
    if not packages:
        _finish(db, history, status="SUCCESS", processed=0)
        return {"source": source, "status": "SUCCESS", "processed": 0, "created": 0, "updated": 0}

    client = OsvClient()
    summaries = client.query_batch(packages)
    ids: dict[str, dict[str, Any]] = {}
    for group in summaries:
        for entry in group:
            osv_id = entry.get("id")
            if osv_id and osv_id not in ids:
                ids[osv_id] = entry

    created = updated = processed = 0
    fetched = 0
    for osv_id, entry in ids.items():
        if fetched >= MAX_OSV_HYDRATIONS:
            break
        payload = entry if entry.get("affected") else client.fetch(osv_id)
        fetched += 1
        record = parse_osv_vulnerability(payload)
        if record is None:
            continue
        _, was_created, changed = vuln_repo.upsert_vulnerability(db, record)
        processed += 1
        if was_created:
            created += 1
        elif changed:
            updated += 1
    db.commit()

    _finish(
        db,
        history,
        status="SUCCESS",
        processed=processed,
        created=created,
        updated=updated,
    )
    logger.info(
        "osv sync completed",
        extra={
            "extra_fields": {
                "packages": len(packages),
                "processed": processed,
                "created": created,
                "updated": updated,
            }
        },
    )
    return {
        "source": source,
        "status": "SUCCESS",
        "processed": processed,
        "created": created,
        "updated": updated,
        "packages": len(packages),
    }


def sync_source(db: Session, source: str, **kwargs: Any) -> dict[str, Any]:
    key = source.upper()
    if key == VulnerabilitySource.CISA_KEV.value:
        return sync_kev(db)
    if key == VulnerabilitySource.NVD.value:
        return sync_nvd(db, **kwargs)
    if key == VulnerabilitySource.OSV.value:
        return sync_osv(db)
    raise ValueError(f"Unknown vulnerability source: {source}")


def sync_history(db: Session, source: str, limit: int = 20) -> list:
    from app.modules.vulnerabilities.models import VulnerabilitySyncHistory

    return list(
        db.execute(
            select(VulnerabilitySyncHistory)
            .where(VulnerabilitySyncHistory.source == source)
            .order_by(VulnerabilitySyncHistory.started_at.desc())
            .limit(limit)
        ).scalars()
    )


def latest_syncs(db: Session) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for source in VulnerabilitySource:
        entry = vuln_repo.last_successful_sync(db, source.value)
        result[source.value] = {
            "last_success_at": entry.finished_at.isoformat() if entry and entry.finished_at else None,
            "records_processed": entry.records_processed if entry else 0,
        }
    total = db.execute(select(Vulnerability.id)).scalars().all()
    result["total_records"] = len(total)
    return result
