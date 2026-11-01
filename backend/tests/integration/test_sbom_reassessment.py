"""Continuous vulnerability reassessment over stored inventory.

Real PostgreSQL and real findings logic. Git, Syft and the scanners are made
explosive in these tests: if reassessment touched a repository or executed a
scanner, the test would fail rather than silently pass.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.enums import FindingStatus
from app.modules.findings import service as findings_service
from app.modules.findings.models import Finding, FindingHistory
from app.modules.sbom import lifecycle
from app.modules.sbom.models import Sbom, SbomMonitoringRun
from app.modules.scanners.base import NormalizedFinding
from app.modules.vulnerabilities import reassessment
from app.modules.vulnerabilities.models import Vulnerability, VulnerabilityAffectedPackage
from app.workers.models import Job
from tests.integration.helpers import (
    IntelSpec,
    add_epss,
    add_vulnerability,
    affected_range,
    make_snapshot,
    package,
)

COMMIT = "a" * 40


def _forbid_repository_access(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args, **_kwargs):
        raise AssertionError("reassessment must not touch a repository")

    monkeypatch.setattr(lifecycle, "clone_repository", explode)
    monkeypatch.setattr(lifecycle, "workspace_for_sbom", explode)
    monkeypatch.setattr(lifecycle, "get_syft", explode)
    monkeypatch.setattr("app.modules.scanners.execution.run_command", explode)


def _snapshot(db: Session, asset_id: uuid.UUID, packages, commit: str = COMMIT):
    snapshot = make_snapshot(db, asset_id=asset_id, packages=packages, commit_sha=commit)
    db.commit()
    return snapshot


def _findings(db: Session, asset_id: uuid.UUID) -> list[Finding]:
    return list(
        db.execute(select(Finding).where(Finding.asset_id == asset_id)).scalars()
    )


def _runs(db: Session, asset_id: uuid.UUID) -> list[SbomMonitoringRun]:
    return list(
        db.execute(
            select(SbomMonitoringRun)
            .where(
                SbomMonitoringRun.asset_id == asset_id,
                SbomMonitoringRun.kind == "VULNERABILITY_REASSESSMENT",
            )
            .order_by(SbomMonitoringRun.started_at.asc())
        ).scalars()
    )


# --------------------------------------------------------------------- detection
def test_new_cve_finds_existing_package_without_any_repository_change(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    snapshot = _snapshot(db, asset.id, [package("requests", "2.31.0")])
    assert _findings(db, asset.id) == []

    # The repository has not changed; only intelligence arrived.
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-test-0001",
            cve_id="CVE-2026-0001",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
            fixed_versions=["2.32.0"],
        ),
    )
    db.commit()

    result = reassessment.reassess_asset(db, asset_id=asset.id, trigger="MANUAL")

    assert result["status"] == "SUCCEEDED"
    assert result["findings_created"] == 1
    finding = _findings(db, asset.id)[0]
    assert finding.discovery_source == "SBOM_REASSESSMENT"
    assert finding.scanner == "osv"
    assert finding.package_name == "requests"
    assert finding.package_version == "2.31.0"
    assert finding.cve_id == "CVE-2026-0001"
    assert finding.metadata_json["inventory_snapshot_id"] == str(snapshot.id)
    assert finding.metadata_json["sbom_commit_sha"] == COMMIT
    assert finding.metadata_json["detection"] == "SBOM_REASSESSMENT"
    assert finding.status == FindingStatus.OPEN.value
    # Nothing ran a scanner or created a scan.
    assert db.execute(select(func.count(Job.id)).where(Job.kind == "SCAN")).scalar_one() == 0
    run = _runs(db, asset.id)[0]
    assert run.status == "SUCCEEDED"
    assert run.components_evaluated == 1
    assert run.metrics["repository_accessed"] is False
    assert run.metrics["scanners_executed"] == []


def test_reassessment_does_not_duplicate_a_scan_finding(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-dup-0001",
            cve_id="CVE-2026-0100",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
        ),
    )
    # A full scan already reported the same vulnerability.
    findings_service.record_findings(
        db,
        asset_id=asset.id,
        scan_id=None,
        normalized=[
            NormalizedFinding(
                scanner="osv",
                rule_id="GHSA-dup-0001",
                title="Already known",
                category="vulnerability",
                severity="HIGH",
                package_name="requests",
                package_version="2.31.0",
                cve_id="CVE-2026-0100",
            )
        ],
        discovery_source="FULL_SCAN",
    )
    db.commit()

    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["findings_created"] == 0
    assert result["findings_updated"] == 1
    rows = _findings(db, asset.id)
    assert len(rows) == 1
    assert rows[0].discovery_source == "FULL_SCAN"
    assert rows[0].metadata_json["evidence_sources"] == ["FULL_SCAN", "SBOM_REASSESSMENT"]


def test_repeated_reassessment_is_idempotent(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-idem-0001",
            cve_id="CVE-2026-0200",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
        ),
    )
    db.commit()

    first = reassessment.reassess_asset(db, asset_id=asset.id)
    history_after_first = db.execute(select(func.count(FindingHistory.id))).scalar_one()
    second = reassessment.reassess_asset(db, asset_id=asset.id)
    history_after_second = db.execute(select(func.count(FindingHistory.id))).scalar_one()

    assert first["findings_created"] == 1
    assert second["findings_created"] == 0
    assert second["findings_updated"] == 1
    assert len(_findings(db, asset.id)) == 1
    assert history_after_first == history_after_second, "no duplicate history events"
    assert len(_runs(db, asset.id)) == 2


def test_new_kev_designation_promotes_severity_and_is_counted(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("flask", "2.0.0")])
    vulnerability = add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-kev-0001",
            cve_id="CVE-2026-0300",
            package_name="flask",
            severity="MEDIUM",
            cvss_score=5.0,
            ranges=affected_range("0", "3.0.0"),
        ),
    )
    db.commit()

    first = reassessment.reassess_asset(db, asset_id=asset.id)
    assert first["findings_created"] == 1
    assert _findings(db, asset.id)[0].severity == "MEDIUM"

    # CISA lists the CVE the next day.
    vulnerability.is_kev = True
    vulnerability.kev_required_action = "Apply updates per vendor instructions."
    db.flush()
    second = reassessment.reassess_asset(db, asset_id=asset.id)

    finding = _findings(db, asset.id)[0]
    assert finding.severity == "HIGH", "KEV promotes to at least HIGH"
    assert finding.metadata_json["intel"]["is_kev"] is True
    assert second["new_kev_findings"] == 1
    assert _runs(db, asset.id)[1].new_kev_findings == 1


def test_all_ranges_of_one_advisory_are_merged(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: an advisory split into several range rows must use all of them.

    GHSA-style advisories often publish one affected row per version track
    (`>=4 <5`, `>=2 <2.0.3`, `>=0 <1.1.13`). Taking only the first row made
    1.1.11 look unaffected and resolved a real finding.
    """
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("brace-expansion", "1.1.11", ecosystem="npm")])
    vulnerability = add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-multi-range",
            cve_id="CVE-2026-2100",
            package_name="brace-expansion",
            ecosystem="npm",
            ranges=affected_range("4.0.0", "5.0.5"),
        ),
    )
    for introduced, fixed in (("3.0.0", "3.0.2"), ("2.0.0", "2.0.3"), ("0", "1.1.13")):
        db.add(
            VulnerabilityAffectedPackage(
                vulnerability_id=vulnerability.id,
                ecosystem="npm",
                package_name="brace-expansion",
                affected_versions=[],
                fixed_versions=[fixed],
                version_ranges=affected_range(introduced, fixed),
            )
        )
    db.commit()

    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["findings_created"] == 1, "the 1.1.x track affects 1.1.11"
    assert result["findings_resolved"] == 0
    finding = _findings(db, asset.id)[0]
    assert finding.status == FindingStatus.OPEN.value
    assert finding.package_version == "1.1.11"


def test_updated_epss_is_recorded_on_the_finding(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("lodash", "4.17.20", ecosystem="npm")])
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-epss-0001",
            cve_id="CVE-2026-0400",
            package_name="lodash",
            ecosystem="npm",
            ranges=affected_range("0", "4.17.21"),
        ),
    )
    add_epss(db, "CVE-2026-0400", 0.12)
    db.commit()

    reassessment.reassess_asset(db, asset_id=asset.id)
    finding = _findings(db, asset.id)[0]
    assert finding.metadata_json["intel"]["epss_score"] == pytest.approx(0.12)

    epss_row = db.execute(
        select(func.count()).select_from(Vulnerability).where(
            Vulnerability.cve_id == "CVE-2026-0400"
        )
    ).scalar_one()
    assert epss_row == 1
    from app.modules.vulnerabilities.models import VulnerabilityEpss

    row = db.execute(select(VulnerabilityEpss)).scalar_one()
    row.score = 0.71
    db.flush()

    result = reassessment.reassess_asset(db, asset_id=asset.id)
    db.expire_all()
    finding = _findings(db, asset.id)[0]
    assert finding.metadata_json["intel"]["epss_score"] == pytest.approx(0.71)
    assert result["status"] == "SUCCEEDED"
    assert _runs(db, asset.id)[1].metrics["epss_updated"] == 1


# ------------------------------------------------------------------- resolution
def test_corrected_intelligence_resolves_with_history(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])
    vulnerability = add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-fix-0001",
            cve_id="CVE-2026-0500",
            package_name="requests",
            ranges=affected_range("0", "2.40.0"),
        ),
    )
    db.commit()
    reassessment.reassess_asset(db, asset_id=asset.id)
    assert _findings(db, asset.id)[0].status == FindingStatus.OPEN.value

    # Upstream corrects the range: the installed version was never affected.
    affected = db.execute(
        select(VulnerabilityAffectedPackage).where(
            VulnerabilityAffectedPackage.vulnerability_id == vulnerability.id
        )
    ).scalar_one()
    affected.version_ranges = affected_range("0", "2.0.0")
    affected.fixed_versions = ["2.0.0"]
    db.flush()

    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["findings_resolved"] == 1
    finding = _findings(db, asset.id)[0]
    assert finding.status == FindingStatus.RESOLVED.value
    assert finding.resolved_at is not None
    notes = [
        row.note
        for row in db.execute(
            select(FindingHistory).where(FindingHistory.finding_id == finding.id)
        ).scalars()
    ]
    assert any("no longer marks the installed version" in (note or "") for note in notes)
    run = _runs(db, asset.id)[1]
    assert run.metrics["resolution_reasons"] == {"version_no_longer_affected": 1}


def test_removed_dependency_resolves_only_with_inventory_provenance(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    first = _snapshot(db, asset.id, [package("requests", "2.31.0")], commit="a" * 40)
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-rm-0001",
            cve_id="CVE-2026-0600",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
        ),
    )
    db.commit()
    reassessment.reassess_asset(db, asset_id=asset.id)
    assert _findings(db, asset.id)[0].status == FindingStatus.OPEN.value

    # The dependency disappears from the next snapshot.
    _snapshot(db, asset.id, [package("flask", "3.0.0")], commit="b" * 40)
    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["findings_resolved"] == 1
    finding = _findings(db, asset.id)[0]
    assert finding.status == FindingStatus.RESOLVED.value
    assert finding.metadata_json["inventory_snapshot_id"] == str(first.id)
    run = _runs(db, asset.id)[1]
    assert run.metrics["resolution_reasons"] == {"package_removed_from_inventory": 1}


def test_finding_without_inventory_provenance_is_not_resolved(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("flask", "3.0.0")])
    findings_service.record_findings(
        db,
        asset_id=asset.id,
        scan_id=None,
        normalized=[
            NormalizedFinding(
                scanner="osv",
                rule_id="GHSA-old-0001",
                title="From an old scan",
                category="vulnerability",
                severity="HIGH",
                package_name="removed-package",
                package_version="1.0.0",
                cve_id="CVE-2026-0700",
            )
        ],
        discovery_source="FULL_SCAN",
    )
    db.commit()

    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["findings_resolved"] == 0
    assert _findings(db, asset.id)[0].status == FindingStatus.OPEN.value
    assert _runs(db, asset.id)[0].metrics["needs_review"] == 1


def test_missing_intelligence_never_resolves_a_finding(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])
    vulnerability = add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-missing-0001",
            cve_id="CVE-2026-0800",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
        ),
    )
    db.commit()
    reassessment.reassess_asset(db, asset_id=asset.id)
    assert _findings(db, asset.id)[0].status == FindingStatus.OPEN.value

    # A failed/partial sync removed the record: absence is not a fix.
    db.delete(vulnerability)
    db.flush()
    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["findings_resolved"] == 0
    assert _findings(db, asset.id)[0].status == FindingStatus.OPEN.value
    assert _runs(db, asset.id)[1].metrics["resolution_reasons"] == {
        "intelligence_missing_for_finding": 1
    }


def test_partial_assessment_never_resolves(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])
    vulnerability = add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-partial-0001",
            cve_id="CVE-2026-0900",
            package_name="requests",
            ranges=affected_range("0", "2.40.0"),
        ),
    )
    db.commit()
    reassessment.reassess_asset(db, asset_id=asset.id)

    # Correction arrives, but the component ceiling is now lower than the
    # inventory: absence can no longer be proven, so nothing may be resolved.
    affected = db.execute(
        select(VulnerabilityAffectedPackage).where(
            VulnerabilityAffectedPackage.vulnerability_id == vulnerability.id
        )
    ).scalar_one()
    affected.version_ranges = affected_range("0", "2.0.0")
    db.flush()
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "sbom_max_reassessment_components", 0, raising=False)

    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["status"] == "PARTIAL"
    assert result["findings_resolved"] == 0
    assert _findings(db, asset.id)[0].status == FindingStatus.OPEN.value
    assert _runs(db, asset.id)[1].metrics["component_limit_reached"] is True


def test_unusable_range_data_is_reported_as_partial_not_safe(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-git-0001",
            cve_id="CVE-2026-1000",
            package_name="requests",
            ranges=[{"type": "GIT", "events": [{"introduced": "0"}]}],
        ),
    )
    db.commit()

    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["status"] == "PARTIAL"
    assert result["findings_created"] == 0
    assert result["unknown_evaluations"] == 1
    run = _runs(db, asset.id)[0]
    assert run.failure_count == 1
    assert "could not be evaluated" in (run.error_message or "")


def test_no_snapshot_is_skipped_explicitly(db: Session, asset_factory) -> None:
    asset = asset_factory()
    result = reassessment.reassess_asset(db, asset_id=asset.id)
    assert result["status"] == "SKIPPED"
    run = _runs(db, asset.id)[0]
    assert run.status == "SKIPPED"
    assert run.skipped_reason == "no SBOM snapshot to evaluate"


def test_reassess_all_covers_assets_with_snapshots(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    with_snapshot = asset_factory()
    asset_factory()  # no snapshot → not evaluated
    _snapshot(db, with_snapshot.id, [package("requests", "2.31.0")])
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-all-0001",
            cve_id="CVE-2026-1100",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
        ),
    )
    db.commit()

    result = reassessment.reassess_all(db, trigger="SCHEDULED")

    assert result["assets"] == 1
    assert result["results"][0]["findings_created"] == 1
    assert len(_runs(db, with_snapshot.id)) == 1


def test_ecosystem_mismatch_does_not_create_a_finding(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0", ecosystem="PyPI")])
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-eco-0001",
            cve_id="CVE-2026-1200",
            package_name="requests",
            ecosystem="npm",
            ranges=affected_range("0", "9.9.9"),
        ),
    )
    db.commit()

    result = reassessment.reassess_asset(db, asset_id=asset.id)

    assert result["findings_created"] == 0
    assert _findings(db, asset.id) == []


def test_concurrent_reassessment_of_same_asset_is_skipped(
    db: Session, asset_factory, engine
) -> None:
    from sqlalchemy import text

    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])
    key = lifecycle._lock_key("reassess", asset.id)

    with engine.connect() as other_connection:
        other_connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": key})
        other_connection.commit()
        try:
            result = reassessment.reassess_asset(db, asset_id=asset.id)
        finally:
            other_connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            other_connection.commit()

    assert result["status"] == "SKIPPED"
    assert result["reason"] == "another reassessment is running"
    assert _runs(db, asset.id) == []


def test_reassessment_rejects_a_snapshot_from_another_asset(
    db: Session, asset_factory
) -> None:
    from app.core.errors import NotFoundError

    first = asset_factory()
    second = asset_factory()
    snapshot = _snapshot(db, first.id, [package("requests", "2.31.0")])

    with pytest.raises(NotFoundError):
        reassessment.reassess_asset(db, asset_id=second.id, sbom_id=snapshot.id)


def test_reassessment_links_run_to_snapshot_and_job(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_repository_access(monkeypatch)
    asset = asset_factory()
    snapshot = _snapshot(db, asset.id, [package("requests", "2.31.0")])
    job, _created = lifecycle.enqueue_reassessment(db, asset, sbom_id=snapshot.id)
    db.commit()

    reassessment.reassess_asset(db, asset_id=asset.id, sbom_id=snapshot.id, job_id=job.id)

    run = _runs(db, asset.id)[0]
    assert run.sbom_id == snapshot.id
    assert run.job_id == job.id
    assert run.trigger == "MANUAL"
    assert isinstance(snapshot, Sbom)
