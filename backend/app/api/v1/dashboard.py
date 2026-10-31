"""Dashboard aggregates for the frontend overview page."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.core.enums import ACTIVE_FINDING_STATUSES, Severity
from app.database.session import get_db
from app.modules.assets.models import Asset
from app.modules.findings.models import Finding
from app.modules.findings.repository import (
    scanner_counts,
    severity_counts,
    status_counts,
)
from app.modules.scans.models import Scan
from app.modules.vulnerabilities.models import Vulnerability

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> dict[str, Any]:
    now = datetime.now(UTC)
    assets_total = int(db.execute(select(func.count(Asset.id))).scalar_one())
    assets_monitored = int(
        db.execute(select(func.count(Asset.id)).where(Asset.monitoring_enabled.is_(True))).scalar_one()
    )

    severities = severity_counts(db)
    statuses = status_counts(db)
    total_findings = sum(severities.values())
    active = sum(statuses.get(status, 0) for status in ACTIVE_FINDING_STATUSES)

    open_critical = int(
        db.execute(
            select(func.count(Finding.id)).where(
                Finding.severity == Severity.CRITICAL.value,
                Finding.status.in_(ACTIVE_FINDING_STATUSES),
            )
        ).scalar_one()
    )
    open_high = int(
        db.execute(
            select(func.count(Finding.id)).where(
                Finding.severity == Severity.HIGH.value,
                Finding.status.in_(ACTIVE_FINDING_STATUSES),
            )
        ).scalar_one()
    )
    kev_findings = int(
        db.execute(
            select(func.count(Finding.id)).where(
                Finding.metadata_json["intel"]["is_kev"].astext == "true",
                Finding.status.in_(ACTIVE_FINDING_STATUSES),
            )
        ).scalar_one()
    )

    scans_24h = int(
        db.execute(
            select(func.count(Scan.id)).where(Scan.created_at >= now - timedelta(hours=24))
        ).scalar_one()
    )
    failed_scans_24h = int(
        db.execute(
            select(func.count(Scan.id)).where(
                Scan.created_at >= now - timedelta(hours=24),
                Scan.status.in_(["FAILED", "CANCELED"]),
            )
        ).scalar_one()
    )

    recent_scans = db.execute(
        select(Scan, Asset.name, Asset.repo_url)
        .join(Asset, Asset.id == Scan.asset_id, isouter=True)
        .order_by(Scan.created_at.desc())
        .limit(8)
    ).all()

    failing_assets = db.execute(
        select(Asset).where(Asset.last_scan_status == "FAILED").order_by(Asset.last_scan_at.desc()).limit(5)
    ).scalars().all()

    active_scans = int(
        db.execute(select(func.count(Scan.id)).where(Scan.status.in_(["PENDING", "RUNNING"]))).scalar_one()
    )
    intel_total = int(db.execute(select(func.count(Vulnerability.id))).scalar_one())
    kev_total = int(
        db.execute(
            select(func.count(Vulnerability.id)).where(Vulnerability.source == "CISA_KEV")
        ).scalar_one()
    )

    return {
        "assets": {"total": assets_total, "monitored": assets_monitored},
        "findings": {
            "total": total_findings,
            "active": active,
            "resolved": statuses.get("RESOLVED", 0),
            "critical_open": open_critical,
            "high_open": open_high,
            "kev": kev_findings,
            "by_severity": [
                {"severity": severity, "total": severities.get(severity, 0)}
                for severity in (
                    Severity.CRITICAL.value,
                    Severity.HIGH.value,
                    Severity.MEDIUM.value,
                    Severity.LOW.value,
                    Severity.INFO.value,
                    Severity.UNKNOWN.value,
                )
            ],
            "by_scanner": [
                {"scanner": scanner, "total": count} for scanner, count in scanner_counts(db)
            ],
            "by_status": [
                {"status": status, "total": count} for status, count in sorted(statuses.items())
            ],
        },
        "scans": {
            "last_24h": scans_24h,
            "failed_last_24h": failed_scans_24h,
            "active": active_scans,
            "recent": [
                {
                    "id": str(scan.id),
                    "asset_id": str(scan.asset_id),
                    "asset_name": asset_name,
                    "status": scan.status,
                    "trigger": scan.trigger,
                    "created_at": scan.created_at.isoformat(),
                    "total_findings": scan.total_findings,
                }
                for scan, asset_name, _repo_url in recent_scans
            ],
        },
        "failing_assets": [
            {
                "id": str(asset.id),
                "name": asset.name,
                "repo_url": asset.repo_url,
                "last_scan_at": asset.last_scan_at.isoformat() if asset.last_scan_at else None,
            }
            for asset in failing_assets
        ],
        "intelligence": {"vulnerabilities": intel_total, "kev": kev_total},
    }
