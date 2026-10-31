"""Finding deduplication, history and lifecycle rules."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from app.core.enums import FindingStatus, ScanStatus
from app.core.errors import ConflictError, ValidationError
from app.modules.findings import service as findings_service
from app.modules.findings.models import Finding
from app.modules.scanners.base import NormalizedFinding
from app.modules.scans.models import Scan


def _finding(rule_id: str = "CVE-2024-1", file_path: str | None = "requirements.txt") -> NormalizedFinding:
    return NormalizedFinding(
        scanner="trivy",
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        category="vulnerability",
        severity="HIGH",
        file_path=file_path,
        package_name="requests" if file_path is None else None,
        package_version="2.19.0" if file_path is None else None,
    )


def _scan(db: Session, asset_id: uuid.UUID, status: str = ScanStatus.COMPLETED.value) -> Scan:
    scan = Scan(asset_id=asset_id, status=status, trigger="MANUAL")
    db.add(scan)
    db.flush()
    return scan


def test_repeated_findings_are_deduplicated(db: Session, asset_factory) -> None:
    asset = asset_factory()
    scan_one = _scan(db, asset.id)
    counts = findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=scan_one.id, normalized=[_finding()]
    )
    assert counts["created"] == 1

    scan_two = _scan(db, asset.id)
    counts = findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=scan_two.id, normalized=[_finding()]
    )
    assert counts == {"created": 0, "updated": 1, "reopened": 0}

    rows = db.query(Finding).filter(Finding.asset_id == asset.id).all()
    assert len(rows) == 1
    assert rows[0].last_scan_id == scan_two.id
    assert rows[0].first_scan_id == scan_one.id


def test_fingerprint_distinguishes_locations(db: Session, asset_factory) -> None:
    asset = asset_factory()
    scan = _scan(db, asset.id)
    findings_service.record_scan_findings(
        db,
        asset_id=asset.id,
        scan_id=scan.id,
        normalized=[_finding(file_path="a.py"), _finding(file_path="b.py")],
    )
    assert db.query(Finding).filter(Finding.asset_id == asset.id).count() == 2


def test_status_transitions_are_validated(db: Session, asset_factory) -> None:
    asset = asset_factory()
    scan = _scan(db, asset.id)
    findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=scan.id, normalized=[_finding()]
    )
    finding = db.query(Finding).one()

    findings_service.update_status(db, finding, "CONFIRMED", actor="tester", note="triaged")
    assert finding.status == FindingStatus.CONFIRMED.value
    history = findings_service.history_for_finding(db, finding.id)
    assert any(entry.event == "STATUS_CHANGED" for entry in history)

    # Confirmed findings can be released back to open.
    findings_service.update_status(db, finding, "OPEN", actor="tester")
    assert finding.status == FindingStatus.OPEN.value

    findings_service.update_status(db, finding, "RESOLVED", actor="tester")
    assert finding.resolved_at is not None

    # Resolved findings may be reopened, but not silently accepted as risk.
    with pytest.raises(ConflictError):
        findings_service.update_status(db, finding, "ACCEPTED_RISK", actor="tester")


def test_unknown_status_is_rejected(db: Session, asset_factory) -> None:
    asset = asset_factory()
    scan = _scan(db, asset.id)
    findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=scan.id, normalized=[_finding()]
    )
    finding = db.query(Finding).one()
    with pytest.raises(ValidationError):
        findings_service.update_status(db, finding, "WONTFIX")


def test_resolution_only_for_successful_scanner(db: Session, asset_factory) -> None:
    asset = asset_factory()
    first = _scan(db, asset.id)
    findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=first.id, normalized=[_finding()]
    )

    second = _scan(db, asset.id)
    # The second scan detected nothing with trivy.
    findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=second.id, normalized=[]
    )
    resolved = findings_service.resolve_missing_findings(
        db, asset_id=asset.id, scan_id=second.id, scanners=["trivy"]
    )
    assert resolved == 1
    finding = db.query(Finding).one()
    assert finding.status == FindingStatus.RESOLVED.value
    assert finding.resolved_at is not None

    events = [entry.event for entry in findings_service.history_for_finding(db, finding.id)]
    assert "AUTO_RESOLVED" in events


def test_resolution_skips_other_scanners(db: Session, asset_factory) -> None:
    asset = asset_factory()
    first = _scan(db, asset.id)
    findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=first.id, normalized=[_finding()]
    )
    second = _scan(db, asset.id)
    # semgrep failed this round, so trivy findings must not be resolved by it.
    resolved = findings_service.resolve_missing_findings(
        db, asset_id=asset.id, scan_id=second.id, scanners=["semgrep"]
    )
    assert resolved == 0
    assert db.query(Finding).one().status == FindingStatus.OPEN.value


def test_rediscovered_resolved_finding_reopens(db: Session, asset_factory) -> None:
    asset = asset_factory()
    first = _scan(db, asset.id)
    findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=first.id, normalized=[_finding()]
    )
    finding = db.query(Finding).one()
    findings_service.update_status(db, finding, "RESOLVED", actor="tester")

    second = _scan(db, asset.id)
    counts = findings_service.record_scan_findings(
        db, asset_id=asset.id, scan_id=second.id, normalized=[_finding()]
    )
    assert counts["reopened"] == 1
    db.refresh(finding)
    assert finding.status == FindingStatus.OPEN.value
    assert finding.resolved_at is None
