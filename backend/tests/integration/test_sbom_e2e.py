"""End-to-end: full scan → SBOM snapshot → continuous reassessment.

One narrative test walks the whole lifecycle with the real pipeline, the real
PostgreSQL queue, real findings and real storage; only external tools are faked.
The second test is the performance proof: reassessment is executed repeatedly
while every repository and scanner entry point is instrumented to record calls.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.enums import JobKind
from app.modules.findings.models import Finding, FindingHistory
from app.modules.sbom import lifecycle, service
from app.modules.sbom.models import Sbom, SbomMonitoringRun
from app.modules.scanners.base import NormalizedFinding, ScannerRun
from app.modules.scanners.syft import SbomDocument, SbomPackageInfo
from app.modules.scans.models import Scan, ScannerExecution
from app.modules.scans.service import create_scan
from app.modules.vulnerabilities import reassessment
from app.workers import pipeline, queue, worker
from app.workers.checkout import Checkout
from app.workers.models import Job
from tests.integration.helpers import (
    FakeProviderClient,
    IntelSpec,
    add_vulnerability,
    affected_range,
    document,
    install_fake_checkout,
    package,
    write_tree,
)
from tests.integration.helpers import (
    FakeSyft as LifecycleSyft,
)

TRIVY_FINDING = NormalizedFinding(
    scanner="trivy",
    rule_id="CVE-2024-9999",
    title="Vulnerable dependency (trivy)",
    category="vulnerability",
    severity="HIGH",
    package_name="requests",
    package_version="2.31.0",
    cve_id="CVE-2024-9999",
    cvss_score=7.5,
)


class _PipelineSyft:
    def __init__(self, packages: list[SbomPackageInfo]) -> None:
        self.packages = packages

    def generate(
        self, workspace: Path, output_dir: Path, sbom_format: str = "CYCLONEDX_JSON"
    ) -> SbomDocument:
        output_dir.mkdir(parents=True, exist_ok=True)
        return SbomDocument(
            content=b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}',
            format="CYCLONEDX_JSON",
            spec_version="1.5",
            tool_version="syft-test",
            packages=self.packages,
        )


class _FakeScanner:
    name = "trivy"

    def __init__(self, findings: list[NormalizedFinding]) -> None:
        self._findings = findings

    def run(self, workspace: Path, report_dir: Path) -> ScannerRun:
        report_dir.mkdir(parents=True, exist_ok=True)
        return ScannerRun(
            scanner=self.name,
            status="SUCCESS",
            findings=self._findings,
            version="test",
            exit_code=0,
            duration_seconds=0.01,
            command={"argv": ["trivy"]},
        )


def _install_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    packages: list[SbomPackageInfo],
    commit: str,
) -> None:
    workspace = write_tree(
        tmp_path / f"scan-{commit[:6]}",
        {"requirements.txt": "requests==2.31.0\n"},
    )

    def fake_clone(*, repo_url, branch, token, destination):  # noqa: ANN001, ARG001
        import shutil

        shutil.copytree(workspace, destination, dirs_exist_ok=True)
        return Checkout(path=destination, branch=branch, commit_sha=commit, provider="github")

    monkeypatch.setattr(pipeline, "clone_repository", fake_clone)
    monkeypatch.setattr(pipeline, "get_syft", lambda: _PipelineSyft(packages))
    monkeypatch.setattr(pipeline, "enabled_scanners", lambda: [_FakeScanner([TRIVY_FINDING])])
    monkeypatch.setattr(pipeline, "correlate_packages", lambda *args, **kwargs: [])


def _run_queued(db: Session, kind: JobKind) -> int:
    """Execute every queued job of ``kind`` through the worker dispatch path."""
    processed = 0
    while True:
        job = db.execute(
            select(Job)
            .where(Job.kind == kind.value, Job.status == "QUEUED")
            .order_by(Job.created_at.asc())
            .limit(1)
        ).scalar_one_or_none()
        if job is None:
            return processed
        job.status = "RUNNING"
        job.attempts += 1
        db.flush()
        worker._run_job(db, job, "e2e-worker")
        queue.mark_succeeded(db, job.id)
        processed += 1


def test_full_lifecycle_from_scan_to_new_vulnerability(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # ---------------------------------------------------------- 1. full scan
    first_commit = "1" * 40
    _install_scan(
        monkeypatch,
        tmp_path,
        packages=[package("requests", "2.31.0")],
        commit=first_commit,
    )
    asset = asset_factory()
    scan = create_scan(db, asset)
    db.commit()
    pipeline.execute_scan(db, scan.id)
    db.refresh(scan)

    assert scan.status == "COMPLETED"
    snapshot = service.latest_sbom_for_asset(db, asset.id)
    assert snapshot is not None
    assert snapshot.creation_reason == "FULL_SCAN"
    assert snapshot.commit_sha == first_commit
    assert snapshot.dependency_fingerprint
    assert snapshot.manifest_fingerprint
    assert snapshot.package_count == 1
    scan_findings = db.execute(select(Finding).where(Finding.asset_id == asset.id)).scalars().all()
    assert any(f.scanner == "trivy" for f in scan_findings)
    baseline_scans = db.execute(select(func.count(Scan.id))).scalar_one()
    baseline_executions = db.execute(select(func.count(ScannerExecution.id))).scalar_one()
    assert baseline_executions == 2, "syft + the fake scanner ran during the scan"

    # ---------------------- 2. intelligence arrives; repository unchanged
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-e2e-0001",
            cve_id="CVE-2026-9001",
            package_name="requests",
            severity="HIGH",
            ranges=affected_range("0", "2.32.0"),
            fixed_versions=["2.32.0"],
        ),
    )
    db.commit()

    lifecycle.enqueue_reassessment(db, asset, trigger="MANUAL")
    db.commit()
    assert _run_queued(db, JobKind.SBOM_VULNERABILITY_REASSESSMENT) == 1

    findings = db.execute(select(Finding).where(Finding.asset_id == asset.id)).scalars().all()
    osv = [row for row in findings if row.scanner == "osv"]
    assert len(osv) == 1
    assert osv[0].cve_id == "CVE-2026-9001"
    assert osv[0].discovery_source == "SBOM_REASSESSMENT"
    assert osv[0].status == "OPEN"
    assert osv[0].metadata_json["inventory_snapshot_id"] == str(snapshot.id)
    # No new scan, no scanner execution: the CVE was found from stored data.
    assert db.execute(select(func.count(Scan.id))).scalar_one() == baseline_scans
    assert (
        db.execute(select(func.count(ScannerExecution.id))).scalar_one()
        == baseline_executions
    )

    # ------------------------------------ 3. business-logic-only commit
    check = lifecycle.check_dependencies(
        db,
        asset_id=asset.id,
        trigger="WEBHOOK",
        client=FakeProviderClient(head="2" * 40, files=["src/app.py", "README.md"]),
    )
    assert check["outcome"] == "NO_DEPENDENCY_CHANGE"
    assert db.execute(select(func.count(Sbom.id))).scalar_one() == 1
    assert (
        db.execute(select(func.count(Job.id)).where(Job.kind == JobKind.SBOM_GENERATE.value))
        .scalar_one()
        == 0
    )

    # ------------------------------------------ 4. dependency change
    check = lifecycle.check_dependencies(
        db,
        asset_id=asset.id,
        trigger="WEBHOOK",
        client=FakeProviderClient(head="3" * 40, files=["requirements.txt", "src/app.py"]),
    )
    assert check["outcome"] == "DEPENDENCY_CHANGED"
    install_fake_checkout(
        monkeypatch,
        write_tree(
            tmp_path / "new-repo",
            {"requirements.txt": "requests==2.20.0\n"},
        ),
        commit_sha="3" * 40,
    )
    monkeypatch.setattr(
        lifecycle,
        "get_syft",
        lambda: LifecycleSyft(document([package("requests", "2.20.0")])),
    )
    assert _run_queued(db, JobKind.SBOM_GENERATE) == 1

    db.expire_all()
    snapshots = db.execute(
        select(Sbom).where(Sbom.asset_id == asset.id).order_by(Sbom.created_at.asc())
    ).scalars().all()
    assert len(snapshots) == 2
    newer = snapshots[-1]
    assert newer.previous_snapshot_id == snapshots[0].id
    assert newer.commit_sha == "3" * 40
    assert newer.creation_reason == "DEPENDENCY_CHANGE"
    assert newer.package_count == 1

    # ------------------------------------------ 5. diff and finding lifecycle
    diff = __import__("app.modules.sbom.diff", fromlist=["diff_packages"]).diff_packages(
        service.packages_for_sbom(db, snapshots[0].id),
        service.packages_for_sbom(db, newer.id),
    )
    assert diff.version_changed == 1
    assert diff.filter("VERSION_CHANGED")[0].version_before == "2.31.0"
    assert diff.filter("VERSION_CHANGED")[0].version_after == "2.20.0"

    assert _run_queued(db, JobKind.SBOM_VULNERABILITY_REASSESSMENT) == 1
    db.expire_all()
    osv = db.execute(
        select(Finding)
        .where(Finding.asset_id == asset.id, Finding.scanner == "osv")
        .order_by(Finding.package_version.asc())
    ).scalars().all()
    assert {row.package_version for row in osv} == {"2.20.0", "2.31.0"}
    old = next(row for row in osv if row.package_version == "2.31.0")
    new = next(row for row in osv if row.package_version == "2.20.0")
    assert old.status == "RESOLVED", "the old version left the composition"
    assert new.status == "OPEN", "the downgraded version is inside the affected range"
    assert new.discovery_source == "SBOM_REASSESSMENT"

    history = db.execute(select(FindingHistory).where(FindingHistory.finding_id == old.id)).scalars().all()
    assert any(row.event == "AUTO_RESOLVED" for row in history)
    assert any("version changed" in (row.note or "") for row in history)

    # Every lifecycle step is visible as an executable record.
    kinds = {
        run.kind
        for run in db.execute(
            select(SbomMonitoringRun).where(SbomMonitoringRun.asset_id == asset.id)
        ).scalars()
    }
    assert kinds == {"DEPENDENCY_CHECK", "SBOM_GENERATION", "VULNERABILITY_REASSESSMENT"}


def test_reassessment_never_clones_or_runs_a_scanner(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"clone": 0, "syft": 0, "scanner": 0, "subprocess": 0}

    def forbid(name: str):
        def _inner(*args, **kwargs):  # noqa: ANN002, ANN003
            calls[name] += 1
            raise AssertionError(f"reassessment must not call {name}")

        return _inner

    monkeypatch.setattr(lifecycle, "clone_repository", forbid("clone"))
    monkeypatch.setattr(lifecycle, "workspace_for_sbom", forbid("clone"))
    monkeypatch.setattr(lifecycle, "get_syft", forbid("syft"))
    monkeypatch.setattr("app.modules.scanners.execution.run_command", forbid("subprocess"))

    asset = asset_factory()
    packages = [package("requests", "2.31.0"), package("flask", "3.0.0"), package("urllib3", "2.2.1")]
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document(packages),
        commit_sha="a" * 40,
    )
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-no-repo-0001",
            cve_id="CVE-2026-9100",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
        ),
    )
    db.commit()
    snapshots_before = db.execute(select(func.count(Sbom.id))).scalar_one()
    scans_before = db.execute(select(func.count(Scan.id))).scalar_one()
    executions_before = db.execute(select(func.count(ScannerExecution.id))).scalar_one()

    runs = [reassessment.reassess_asset(db, asset_id=asset.id) for _ in range(5)]

    assert calls == {"clone": 0, "syft": 0, "scanner": 0, "subprocess": 0}
    assert db.execute(select(func.count(Sbom.id))).scalar_one() == snapshots_before
    assert db.execute(select(func.count(Scan.id))).scalar_one() == scans_before
    assert db.execute(select(func.count(ScannerExecution.id))).scalar_one() == executions_before
    assert all(run["status"] == "SUCCEEDED" for run in runs)
    assert runs[0]["findings_created"] == 1
    assert all(run["findings_created"] == 0 for run in runs[1:])
    assert all(run["components_evaluated"] == 3 for run in runs)
    stored = db.execute(
        select(SbomMonitoringRun).where(
            SbomMonitoringRun.kind == "VULNERABILITY_REASSESSMENT"
        )
    ).scalars().all()
    assert all(run.metrics["repository_accessed"] is False for run in stored)
    assert all(run.metrics["scanners_executed"] == [] for run in stored)
    assert all(run.duration_ms is not None for run in stored)
    assert isinstance(asset.id, uuid.UUID)
