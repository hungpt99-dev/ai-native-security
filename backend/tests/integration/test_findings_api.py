"""Finding API: filtering, sorting, pagination and status updates."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.modules.findings import service as findings_service
from app.modules.scanners.base import NormalizedFinding
from app.modules.scans.models import Scan


def _seed(db: Session, asset_id: uuid.UUID, findings: list[NormalizedFinding]) -> uuid.UUID:
    scan = Scan(asset_id=asset_id, status="COMPLETED", trigger="MANUAL", total_findings=len(findings))
    db.add(scan)
    db.flush()
    findings_service.record_scan_findings(
        db, asset_id=asset_id, scan_id=scan.id, normalized=findings
    )
    db.commit()
    return scan.id


def _finding(rule: str, severity: str, scanner: str = "trivy") -> NormalizedFinding:
    return NormalizedFinding(
        scanner=scanner,
        rule_id=rule,
        title=f"Issue {rule}",
        category="vulnerability",
        severity=severity,
        package_name="package-x",
        package_version="1.0.0",
    )


def test_list_findings_with_filters(client: TestClient, db: Session, asset_factory) -> None:
    asset = asset_factory()
    other = asset_factory()
    _seed(db, asset.id, [_finding("CVE-1", "CRITICAL"), _finding("CVE-2", "LOW")])
    _seed(db, other.id, [_finding("R-1", "HIGH", scanner="semgrep")])

    all_findings = client.get("/api/v1/findings").json()
    assert all_findings["total"] == 3

    critical = client.get("/api/v1/findings", params={"severity": "CRITICAL"}).json()
    assert critical["total"] == 1

    by_scanner = client.get("/api/v1/findings", params={"scanner": "semgrep"}).json()
    assert by_scanner["total"] == 1

    by_asset = client.get("/api/v1/findings", params={"asset_id": str(asset.id)}).json()
    assert by_asset["total"] == 2

    search = client.get("/api/v1/findings", params={"search": "CVE-2"}).json()
    assert search["total"] == 1

    paged = client.get("/api/v1/findings", params={"page": 1, "page_size": 2}).json()
    assert len(paged["items"]) == 2
    assert paged["pages"] == 2

    sorted_rows = client.get(
        "/api/v1/findings", params={"sort_by": "severity", "sort_order": "asc"}
    ).json()["items"]
    assert sorted_rows[0]["severity"] == "CRITICAL"


def test_finding_detail_and_status_update(client: TestClient, db: Session, asset_factory) -> None:
    asset = asset_factory()
    _seed(db, asset.id, [_finding("CVE-9", "HIGH")])
    listing = client.get("/api/v1/findings").json()
    finding_id = listing["items"][0]["id"]

    detail = client.get(f"/api/v1/findings/{finding_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["asset_name"] == asset.name
    assert body["history"][0]["event"] == "DETECTED"

    updated = client.patch(
        f"/api/v1/findings/{finding_id}/status",
        json={"status": "CONFIRMED", "note": "validated by appsec"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["status"] == "CONFIRMED"
    assert any(entry["event"] == "STATUS_CHANGED" for entry in updated.json()["history"])

    invalid = client.patch(
        f"/api/v1/findings/{finding_id}/status", json={"status": "FALSE_POSITIVE"}
    )
    # CONFIRMED -> FALSE_POSITIVE is allowed, then FALSE_POSITIVE -> RESOLVED is not.
    assert invalid.status_code == 200
    not_allowed = client.patch(
        f"/api/v1/findings/{finding_id}/status", json={"status": "RESOLVED"}
    )
    assert not_allowed.status_code == 409


def test_invalid_status_value_is_rejected(client: TestClient, db: Session, asset_factory) -> None:
    asset = asset_factory()
    _seed(db, asset.id, [_finding("CVE-10", "LOW")])
    finding_id = client.get("/api/v1/findings").json()["items"][0]["id"]
    response = client.patch(f"/api/v1/findings/{finding_id}/status", json={"status": "NOPE"})
    assert response.status_code == 422
