"""SBOM lifecycle: dependency detection, snapshot generation, freshness.

Real PostgreSQL; only git, the provider API and Syft are faked. Every assertion
about job rows, monitoring runs and snapshots is made against the database.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import DependencyChangeOutcome, JobKind, JobStatus, SbomFreshness
from app.core.errors import ExternalServiceError
from app.modules.sbom import lifecycle, service
from app.modules.sbom.models import Sbom, SbomMonitoringRun
from app.modules.scanners.syft import SbomDocument, SbomPackageInfo
from app.workers.models import Job
from tests.integration.helpers import (
    FakeProviderClient,
    FakeSyft,
    document,
    install_fake_checkout,
    package,
    write_tree,
)

HEAD = "b" * 40
SNAPSHOT_COMMIT = "a" * 40


def _jobs(db: Session, kind: JobKind) -> list[Job]:
    return list(db.execute(select(Job).where(Job.kind == kind.value)).scalars())


def _runs(db: Session, asset_id: uuid.UUID, kind: str) -> list[SbomMonitoringRun]:
    return list(
        db.execute(
            select(SbomMonitoringRun)
            .where(
                SbomMonitoringRun.asset_id == asset_id,
                SbomMonitoringRun.kind == kind,
            )
            .order_by(SbomMonitoringRun.started_at.asc())
        ).scalars()
    )


def _check(db: Session, asset_id: uuid.UUID, client: FakeProviderClient, **kwargs):
    return lifecycle.check_dependencies(
        db, asset_id=asset_id, trigger="MANUAL", client=client, **kwargs
    )


# --------------------------------------------------------------- change checks
def test_first_check_without_snapshot_queues_initial_generation(
    db: Session, asset_factory
) -> None:
    asset = asset_factory()
    result = _check(db, asset.id, FakeProviderClient(head=HEAD))

    assert result["outcome"] == DependencyChangeOutcome.NO_SNAPSHOT.value
    jobs = _jobs(db, JobKind.SBOM_GENERATE)
    assert len(jobs) == 1
    assert jobs[0].payload["reason"] == "INITIAL"
    assert jobs[0].payload["head_sha"] == HEAD
    run = _runs(db, asset.id, "DEPENDENCY_CHECK")[0]
    assert run.status == "SUCCEEDED"
    assert run.skipped_reason


def test_unchanged_commit_does_not_queue_any_generation(db: Session, asset_factory) -> None:
    asset = asset_factory()
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    db.commit()

    result = _check(db, asset.id, FakeProviderClient(head=SNAPSHOT_COMMIT))

    assert result["outcome"] == DependencyChangeOutcome.UNCHANGED.value
    assert _jobs(db, JobKind.SBOM_GENERATE) == []
    assert _runs(db, asset.id, "DEPENDENCY_CHECK")[0].head_commit_sha == SNAPSHOT_COMMIT


def test_business_logic_only_commit_does_not_generate_sbom(
    db: Session, asset_factory
) -> None:
    asset = asset_factory()
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    db.commit()

    result = _check(
        db,
        asset.id,
        FakeProviderClient(head=HEAD, files=["src/service.py", "src/views.py", "README.md"]),
    )

    assert result["outcome"] == DependencyChangeOutcome.NO_DEPENDENCY_CHANGE.value
    assert _jobs(db, JobKind.SBOM_GENERATE) == [], "a business-logic commit must not regenerate"
    run = _runs(db, asset.id, "DEPENDENCY_CHECK")[0]
    assert run.metrics["dependency_input_count"] == 0
    assert run.metrics["changed_paths_total"] == 3


def test_lockfile_change_queues_generation_and_is_idempotent(
    db: Session, asset_factory
) -> None:
    asset = asset_factory()
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    db.commit()

    client = FakeProviderClient(head=HEAD, files=["package.json", "package-lock.json", "src/a.py"])
    first = _check(db, asset.id, client)
    second = _check(db, asset.id, client)

    assert first["outcome"] == DependencyChangeOutcome.DEPENDENCY_CHANGED.value
    assert second["outcome"] == DependencyChangeOutcome.DEPENDENCY_CHANGED.value
    jobs = _jobs(db, JobKind.SBOM_GENERATE)
    assert len(jobs) == 1, "the same commit must not enqueue two generation jobs"
    assert jobs[0].payload["reason"] == "DEPENDENCY_CHANGE"
    run = _runs(db, asset.id, "DEPENDENCY_CHECK")[-1]
    assert run.metrics["ecosystems"] == ["npm"]
    assert "package-lock.json" in run.metrics["dependency_inputs"]


def test_provider_failure_is_unknown_not_up_to_date(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = asset_factory()
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    db.commit()
    # The ls-remote fallback must not reach the network in tests.
    monkeypatch.setattr(lifecycle, "remote_head", lambda **_: None)

    result = _check(db, asset.id, FakeProviderClient(fail=True))

    assert result["outcome"] == DependencyChangeOutcome.UNKNOWN.value
    assert _jobs(db, JobKind.SBOM_GENERATE) == []
    run = _runs(db, asset.id, "DEPENDENCY_CHECK")[0]
    assert run.status == "PARTIAL"
    assert run.error_message
    status = lifecycle.asset_monitoring_status(db, asset.id)
    assert status["freshness"] == SbomFreshness.UNKNOWN.value
    assert status["monitoring_status"] != "HEALTHY"


def test_partial_file_list_cannot_prove_absence_of_change(
    db: Session, asset_factory
) -> None:
    asset = asset_factory()
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    db.commit()

    result = _check(
        db,
        asset.id,
        FakeProviderClient(head=HEAD, files=["src/a.py"], truncated=True),
    )

    assert result["outcome"] == DependencyChangeOutcome.DEPENDENCY_CHANGED.value
    run = _runs(db, asset.id, "DEPENDENCY_CHECK")[0]
    assert run.metrics["compare_truncated"] is True
    assert run.metrics["reason"] == "provider_truncated_path_list"


def test_snapshot_without_commit_is_unknown_and_gets_a_baseline(
    db: Session, asset_factory
) -> None:
    asset = asset_factory()
    # Simulates a snapshot created before commit tracking existed.
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
    )
    db.commit()

    result = _check(db, asset.id, FakeProviderClient(head=HEAD, files=["src/app.py"]))

    assert result["outcome"] == DependencyChangeOutcome.UNKNOWN.value
    run = _runs(db, asset.id, "DEPENDENCY_CHECK")[0]
    assert run.status == "PARTIAL"
    assert run.metrics["reason"] == "snapshot_commit_unknown"
    jobs = _jobs(db, JobKind.SBOM_GENERATE)
    assert len(jobs) == 1 and jobs[0].payload["reason"] == "BASELINE"
    status = lifecycle.asset_monitoring_status(db, asset.id)
    # A queued baseline generation is pending; either way it is never "current".
    assert status["freshness"] in {SbomFreshness.UNKNOWN.value, SbomFreshness.PENDING.value}
    for job in jobs:
        job.status = JobStatus.CANCELED.value
    db.flush()
    status = lifecycle.asset_monitoring_status(db, asset.id)
    assert status["freshness"] == SbomFreshness.UNKNOWN.value
    assert "no recorded commit" in status["freshness_detail"]


def test_branch_change_forces_a_new_snapshot(db: Session, asset_factory) -> None:
    asset = asset_factory(default_branch="release")
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    db.commit()

    result = lifecycle.check_dependencies(
        db, asset_id=asset.id, trigger="MANUAL", client=FakeProviderClient(head=HEAD)
    )

    assert result["outcome"] == DependencyChangeOutcome.DEPENDENCY_CHANGED.value
    run = _runs(db, asset.id, "DEPENDENCY_CHECK")[0]
    assert run.metrics["reason"] == "branch_changed"
    assert len(_jobs(db, JobKind.SBOM_GENERATE)) == 1


# ------------------------------------------------------------------ generation
def _prepare_generation(
    db: Session,
    asset,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    packages: list[SbomPackageInfo] | None = None,
    commit: str = HEAD,
    fail: Exception | None = None,
) -> FakeSyft:
    workspace = write_tree(
        tmp_path / "repo",
        {
            "requirements.txt": "requests==2.31.0\n",
            "pyproject.toml": "[project]\nname='demo'\n",
            "src/app.py": "print('hello')\n",
        },
    )
    install_fake_checkout(monkeypatch, workspace, commit_sha=commit)
    fake_syft = FakeSyft(document(packages or [package("requests", "2.31.0")]), fail=fail)
    monkeypatch.setattr(lifecycle, "get_syft", lambda: fake_syft)
    return fake_syft


def test_generation_stores_snapshot_with_provenance(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = asset_factory()
    fake_syft = _prepare_generation(db, asset, monkeypatch, tmp_path)

    result = lifecycle.generate_snapshot(
        db, asset_id=asset.id, trigger="MANUAL", reason="MANUAL"
    )

    assert result["status"] == "SUCCEEDED"
    snapshot = db.get(Sbom, uuid.UUID(result["snapshot_id"]))
    assert snapshot is not None
    assert snapshot.commit_sha == HEAD
    assert snapshot.branch == "main"
    assert snapshot.creation_reason == "MANUAL"
    assert snapshot.generation_status == "READY"
    assert snapshot.dependency_fingerprint
    assert snapshot.manifest_fingerprint
    assert snapshot.generated_at is not None
    assert snapshot.previous_snapshot_id is None
    assert snapshot.package_count == 1
    assert fake_syft.calls == 1
    # The generation run is recorded and the snapshot is linked to it.
    run = _runs(db, asset.id, "SBOM_GENERATION")[0]
    assert run.status == "SUCCEEDED" and run.sbom_id == snapshot.id
    assert run.metrics["manifest_files"] == ["pyproject.toml", "requirements.txt"]
    # A reassessment job is queued for the new inventory, and only one.
    jobs = _jobs(db, JobKind.SBOM_VULNERABILITY_REASSESSMENT)
    assert len(jobs) == 1 and jobs[0].payload["sbom_id"] == str(snapshot.id)


def test_repeated_generation_with_identical_inventory_is_skipped(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = asset_factory()
    fake_syft = _prepare_generation(db, asset, monkeypatch, tmp_path)

    first = lifecycle.generate_snapshot(db, asset_id=asset.id)
    second = lifecycle.generate_snapshot(db, asset_id=asset.id)

    assert first["status"] == "SUCCEEDED"
    assert second["status"] == "SKIPPED"
    assert second["reason"] == "identical_inventory"
    assert second["snapshot_id"] == first["snapshot_id"]
    assert fake_syft.calls == 2, "Syft ran, but no duplicate snapshot was stored"
    assert db.execute(select(func.count(Sbom.id))).scalar_one() == 1
    runs = _runs(db, asset.id, "SBOM_GENERATION")
    assert [run.status for run in runs] == ["SUCCEEDED", "SKIPPED"]


def test_generation_failure_is_recorded_and_creates_no_snapshot(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = asset_factory()
    _prepare_generation(
        db, asset, monkeypatch, tmp_path, fail=ExternalServiceError("syft crashed")
    )

    with pytest.raises(ExternalServiceError):
        lifecycle.generate_snapshot(db, asset_id=asset.id)

    assert db.execute(select(func.count(Sbom.id))).scalar_one() == 0
    run = _runs(db, asset.id, "SBOM_GENERATION")[0]
    assert run.status == "FAILED"
    assert "syft crashed" in (run.error_message or "")
    status = lifecycle.asset_monitoring_status(db, asset.id)
    assert status["freshness"] == SbomFreshness.MISSING.value


def test_snapshot_history_is_immutable(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = asset_factory()
    _prepare_generation(db, asset, monkeypatch, tmp_path)
    first = lifecycle.generate_snapshot(db, asset_id=asset.id)
    first_snapshot = db.get(Sbom, uuid.UUID(first["snapshot_id"]))
    first_checksum = first_snapshot.sha256
    first_document = service.download_sbom(db, first_snapshot.id)[0]

    # New commit + upgraded dependency → a new snapshot, not an update.
    _prepare_generation(
        db,
        asset,
        monkeypatch,
        tmp_path / "second",
        packages=[package("requests", "2.32.0")],
        commit="d" * 40,
    )
    second = lifecycle.generate_snapshot(db, asset_id=asset.id)

    assert second["snapshot_id"] != first["snapshot_id"]
    db.expire_all()
    reloaded = db.get(Sbom, first_snapshot.id)
    assert reloaded is not None
    assert reloaded.sha256 == first_checksum
    assert service.download_sbom(db, reloaded.id)[0] == first_document
    newer = db.get(Sbom, uuid.UUID(second["snapshot_id"]))
    assert newer is not None and newer.previous_snapshot_id == reloaded.id
    assert second["diff"]["version_changed"] == 1
    assert db.execute(select(func.count(Sbom.id))).scalar_one() == 2


def test_concurrent_generation_is_skipped_by_advisory_lock(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, engine
) -> None:
    asset = asset_factory()
    _prepare_generation(db, asset, monkeypatch, tmp_path)
    key = lifecycle._lock_key("generate", asset.id)

    with engine.connect() as other_connection:
        other_connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": key})
        other_connection.commit()
        try:
            result = lifecycle.generate_snapshot(db, asset_id=asset.id)
        finally:
            other_connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            other_connection.commit()

    assert result["status"] == "SKIPPED"
    assert result["reason"] == "another sbom generation is running"
    assert db.execute(select(func.count(Sbom.id))).scalar_one() == 0


# ------------------------------------------------------------------- freshness
def test_freshness_requires_positive_evidence(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = asset_factory()
    status = lifecycle.asset_monitoring_status(db, asset.id)
    assert status["freshness"] == SbomFreshness.MISSING.value

    _prepare_generation(db, asset, monkeypatch, tmp_path)
    lifecycle.generate_snapshot(db, asset_id=asset.id)
    status = lifecycle.asset_monitoring_status(db, asset.id)
    # A snapshot exists, but no dependency check has verified it against head.
    assert status["freshness"] == SbomFreshness.UNKNOWN.value
    assert "no dependency check" in status["freshness_detail"]

    _check(db, asset.id, FakeProviderClient(head=HEAD, files=["src/app.py"]))
    status = lifecycle.asset_monitoring_status(db, asset.id)
    assert status["freshness"] == SbomFreshness.CURRENT.value

    # Dependency change detected → the queued generation makes it pending.
    _check(db, asset.id, FakeProviderClient(head="e" * 40, files=["requirements.txt"]))
    status = lifecycle.asset_monitoring_status(db, asset.id)
    assert status["freshness"] == SbomFreshness.PENDING.value
    assert status["pending"]["dependency_change_pending"] is True

    # If the queued work is dropped, freshness must fall back to STALE.
    for job in _jobs(db, JobKind.SBOM_GENERATE):
        job.status = JobStatus.CANCELED.value
    db.flush()
    status = lifecycle.asset_monitoring_status(db, asset.id)
    assert status["freshness"] == SbomFreshness.STALE.value

    # A failed regeneration is reported as FAILED, never as current.
    _prepare_generation(
        db,
        asset,
        monkeypatch,
        tmp_path / "failing",
        fail=ExternalServiceError("syft crashed"),
        commit="f" * 40,
    )
    with pytest.raises(ExternalServiceError):
        lifecycle.generate_snapshot(db, asset_id=asset.id)
    status = lifecycle.asset_monitoring_status(db, asset.id)
    assert status["freshness"] == SbomFreshness.FAILED.value
    assert "failed" in status["freshness_detail"]


def test_status_reports_counts_and_schedule_links(db: Session, asset_factory) -> None:
    asset = asset_factory()
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    db.commit()

    from app.scheduler.scheduler import ensure_default_schedules, sync_asset_schedules

    ensure_default_schedules(db)
    sync_asset_schedules(db)
    status = lifecycle.asset_monitoring_status(db, asset.id)

    assert status["latest_snapshot"]["commit_sha"] == SNAPSHOT_COMMIT
    assert status["latest_snapshot"]["package_count"] == 1
    assert status["monitoring_status"] == "UNKNOWN", "no reassessment has run yet"
    assert status["next_dependency_check"] is not None
    assert status["next_reassessment"] is not None
    assert status["pending"]["sbom_generation"] is False


def test_summary_counts_avoided_scans(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = asset_factory()
    _prepare_generation(db, asset, monkeypatch, tmp_path)
    lifecycle.generate_snapshot(db, asset_id=asset.id)
    _check(db, asset.id, FakeProviderClient(head=HEAD, files=["src/app.py"]))
    _check(db, asset.id, FakeProviderClient(head="9" * 40, files=["src/app.py"]))

    summary = lifecycle.monitoring_summary(db)

    assert summary["dependency_checks"] == 2
    # One check found head == snapshot commit, the other proved the composition
    # unchanged; both replaced a full scan.
    assert summary["dependency_checks_unchanged"] == 2
    assert summary["sbom_generations"] == 1
    assert summary["estimated_full_scans_avoided"] == 2
    assert summary["estimated_repository_checkouts_avoided"] == 2
    assert summary["estimated_scanner_executions_avoided"] >= 0
    assert summary["avg_dependency_check_ms"] is not None


def test_manual_actions_enqueue_deduplicated_jobs(db: Session, asset_factory) -> None:
    asset = asset_factory()
    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    db.commit()

    job_a, created_a = lifecycle.enqueue_check(db, asset, trigger="MANUAL")
    job_b, created_b = lifecycle.enqueue_check(db, asset, trigger="MANUAL")
    assert created_a is True and created_b is False and job_a.id == job_b.id

    gen_a, _ = lifecycle.enqueue_generation(db, asset, trigger="MANUAL")
    gen_b, created = lifecycle.enqueue_generation(db, asset, trigger="MANUAL")
    assert gen_a.id == gen_b.id and created is False

    re_a, _ = lifecycle.enqueue_reassessment(db, asset, trigger="MANUAL")
    re_b, created = lifecycle.enqueue_reassessment(db, asset, trigger="MANUAL")
    assert re_a.id == re_b.id and created is False

    assert db.execute(select(func.count(Job.id))).scalar_one() == 3


def test_run_payload_reports_duration(db: Session, asset_factory) -> None:
    asset = asset_factory()
    run = lifecycle.start_run(
        db, asset_id=asset.id, kind="DEPENDENCY_CHECK", trigger="MANUAL"
    )
    lifecycle.finish_run(
        db, run, status="SUCCEEDED", outcome="UNCHANGED", metrics={"head_source": "test"}
    )
    payload = lifecycle._run_payload(run)
    assert payload is not None
    assert payload["duration_ms"] is not None and payload["duration_ms"] >= 0
    assert payload["metrics"] == {"head_source": "test"}
    assert payload["finished_at"] is not None
    assert datetime.fromisoformat(payload["started_at"]) <= datetime.now(UTC) + timedelta(
        seconds=1
    )


def test_sbom_document_checksum_is_not_the_dependency_fingerprint(
    db: Session, asset_factory
) -> None:
    asset = asset_factory()
    packages = [package("requests", "2.31.0")]
    first = service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document(packages, content=b'{"a": 1}'),
        commit_sha=SNAPSHOT_COMMIT,
        branch="main",
    )
    second = service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document(packages, content=b'{"a": 2}'),
        commit_sha="1" * 40,
        branch="main",
    )
    assert first.sha256 != second.sha256
    assert first.dependency_fingerprint == second.dependency_fingerprint
    assert first.sha256 != first.dependency_fingerprint


def test_direct_and_transitive_counts_are_recorded_when_graph_exists(
    db: Session, asset_factory
) -> None:
    asset = asset_factory()
    packages = [package("flask", "3.0.0"), package("werkzeug", "3.0.1")]
    doc: SbomDocument = document(packages, direct_keys={("flask", "3.0.0")})
    snapshot = service.store_sbom(
        db, asset_id=asset.id, scan_id=None, document=doc, commit_sha=SNAPSHOT_COMMIT
    )
    assert snapshot.direct_package_count == 1
    assert snapshot.transitive_package_count == 1
    assert get_settings().sbom_monitoring_enabled is True
