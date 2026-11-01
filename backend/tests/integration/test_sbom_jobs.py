"""Job processing for the SBOM lifecycle: dispatch, retry, recovery, idempotency."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import JobKind, JobStatus
from app.core.errors import ExternalServiceError
from app.modules.sbom import lifecycle
from app.modules.sbom.models import Sbom, SbomMonitoringRun
from app.modules.vulnerabilities import reassessment
from app.workers import queue, worker
from app.workers.models import Job
from tests.integration.helpers import (
    FakeSyft,
    IntelSpec,
    add_vulnerability,
    affected_range,
    document,
    install_fake_checkout,
    package,
    write_tree,
)


def _make_job(db: Session, kind: JobKind, payload: dict) -> Job:
    job = queue.enqueue(db, kind, payload)
    db.commit()
    return job


def test_change_check_job_runs_through_the_worker(db: Session, asset_factory) -> None:
    asset = asset_factory()
    job = _make_job(
        db,
        JobKind.SBOM_CHANGE_CHECK,
        {"asset_id": str(asset.id), "trigger": "SCHEDULED", "head_sha": "b" * 40},
    )
    # No snapshot yet → the check must enqueue an initial generation.
    worker._run_job(db, job, "worker-test")

    run = db.execute(
        select(SbomMonitoringRun).where(SbomMonitoringRun.asset_id == asset.id)
    ).scalar_one()
    assert run.kind == "DEPENDENCY_CHECK"
    assert run.job_id == job.id
    assert run.outcome == "NO_SNAPSHOT"
    assert db.execute(select(Job).where(Job.kind == JobKind.SBOM_GENERATE.value)).scalar_one()


def test_generation_job_dispatches_to_syft_only(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = asset_factory()
    workspace = write_tree(tmp_path / "repo", {"package.json": "{}", "src/app.ts": "x"})
    install_fake_checkout(monkeypatch, workspace, commit_sha="c" * 40)
    fake_syft = FakeSyft(document([package("lodash", "4.17.21", ecosystem="npm")]))
    monkeypatch.setattr(lifecycle, "get_syft", lambda: fake_syft)

    job = _make_job(
        db,
        JobKind.SBOM_GENERATE,
        {"asset_id": str(asset.id), "reason": "INITIAL", "trigger": "SCHEDULED"},
    )
    worker._run_job(db, job, "worker-test")

    snapshot = db.execute(select(Sbom)).scalar_one()
    assert snapshot.creation_reason == "INITIAL"
    assert snapshot.commit_sha == "c" * 40
    assert fake_syft.calls == 1
    # No scan, no scanner execution: SBOM generation is not a security scan.
    assert db.execute(select(Job).where(Job.kind == JobKind.SCAN.value)).scalar_one_or_none() is None
    assert db.execute(
        select(SbomMonitoringRun).where(SbomMonitoringRun.kind == "SBOM_GENERATION")
    ).scalar_one().status == "SUCCEEDED"


def test_reassessment_job_is_idempotent_on_replay(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "clone_repository", lambda **_: pytest.fail("no clone"))
    asset = asset_factory()
    from app.modules.sbom import service

    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha="a" * 40,
    )
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-job-0001",
            cve_id="CVE-2026-3000",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
        ),
    )
    db.commit()
    job = _make_job(
        db,
        JobKind.SBOM_VULNERABILITY_REASSESSMENT,
        {"asset_id": str(asset.id), "trigger": "SCHEDULED"},
    )

    worker._run_job(db, job, "worker-test")
    worker._run_job(db, job, "worker-test")

    from app.modules.findings.models import Finding

    assert db.execute(select(Finding)).scalars().all().__len__() == 1
    runs = db.execute(
        select(SbomMonitoringRun).where(
            SbomMonitoringRun.kind == "VULNERABILITY_REASSESSMENT"
        )
    ).scalars().all()
    assert len(runs) == 2, "each execution is recorded"
    assert [run.findings_created for run in runs] == [1, 0]


def test_ai_analysis_is_queued_only_when_policy_allows(
    db: Session, asset_factory, settings
) -> None:
    asset = asset_factory()
    from app.modules.findings import service as findings_service
    from app.modules.findings.models import Finding
    from app.modules.scanners.base import NormalizedFinding

    findings_service.record_findings(
        db,
        asset_id=asset.id,
        scan_id=None,
        normalized=[
            NormalizedFinding(
                scanner="osv",
                rule_id="GHSA-ai-0001",
                title="AI gate",
                category="vulnerability",
                severity="HIGH",
                package_name="left-pad",
                package_version="1.0.0",
                cve_id="CVE-2026-4000",
            )
        ],
        discovery_source="SBOM_REASSESSMENT",
    )
    db.commit()
    finding_id = db.execute(select(Finding.id)).scalar_one()

    settings.ai_enabled = False
    from app.workers import automation

    assert automation.enqueue_auto_analysis(db, [finding_id], origin="TEST") == 0

    settings.ai_enabled = True
    settings.ai_auto_analyze = True
    settings.ai_auto_analyze_min_severity = "HIGH"
    assert automation.enqueue_auto_analysis(db, [finding_id], origin="TEST") == 1
    assert automation.enqueue_auto_analysis(db, [finding_id], origin="TEST") == 0
    jobs = db.execute(select(Job).where(Job.kind == JobKind.AI_RISK.value)).scalars().all()
    assert len(jobs) == 1


def test_failure_backoff_and_exhaustion(db: Session) -> None:
    job = queue.enqueue(db, JobKind.SBOM_GENERATE, {"asset_id": str(uuid.uuid4())})
    db.commit()
    job.status = JobStatus.RUNNING.value
    job.attempts = 1
    db.flush()

    queue.mark_failed(db, job.id, "syft crashed")
    db.refresh(job)
    assert job.status == JobStatus.QUEUED.value
    assert job.last_error == "syft crashed"
    assert job.run_after > datetime.now(UTC) + timedelta(seconds=5)

    job.attempts = job.max_attempts
    queue.mark_failed(db, job.id, "still failing")
    db.refresh(job)
    assert job.status == JobStatus.FAILED.value
    assert job.finished_at is not None


def test_stale_job_is_recovered_after_worker_crash(db: Session, settings) -> None:
    job = queue.enqueue(db, JobKind.SBOM_CHANGE_CHECK, {"asset_id": str(uuid.uuid4())})
    db.commit()
    job.status = JobStatus.RUNNING.value
    job.attempts = 1
    job.heartbeat_at = datetime.now(UTC) - timedelta(seconds=settings.job_stale_after_seconds + 60)
    job.locked_by = "crashed-worker"
    db.flush()

    assert queue.recover_stale_jobs(db) == 1
    db.refresh(job)
    assert job.status == JobStatus.QUEUED.value
    assert job.locked_by is None
    assert job.heartbeat_at is not None  # recovery does not erase the last seen beat


def test_already_running_job_is_not_claimed_twice(db: Session) -> None:
    queue.enqueue(db, JobKind.SBOM_GENERATE, {"asset_id": str(uuid.uuid4())})
    db.commit()

    first = queue.claim_next(db, "worker-a")
    second = queue.claim_next(db, "worker-a")

    assert first is not None
    assert second is None
    assert first.status == JobStatus.RUNNING.value


def test_daily_monitoring_schedule_does_not_enqueue_scans(
    db: Session, settings
) -> None:
    from app.scheduler.scheduler import claim_due_schedules, ensure_default_schedules

    settings.sbom_monitoring_enabled = True
    ensure_default_schedules(db)
    # Only the global schedules exist here (no per-asset scan schedules).
    claim_due_schedules(db)

    kinds = {
        job.kind for job in db.execute(select(Job)).scalars().all()
    }
    assert JobKind.SBOM_VULNERABILITY_REASSESSMENT.value in kinds
    assert JobKind.SCAN.value not in kinds
    assert JobKind.SBOM_GENERATE.value not in kinds

    reassessment_jobs = db.execute(
        select(Job).where(Job.kind == JobKind.SBOM_VULNERABILITY_REASSESSMENT.value)
    ).scalars().all()
    assert len(reassessment_jobs) == 1
    assert reassessment_jobs[0].payload == {"trigger": "SCHEDULED"}


def test_scheduler_enqueues_a_check_per_asset_and_deduplicates(
    db: Session, asset_factory, settings
) -> None:
    from app.scheduler.scheduler import claim_due_schedules, sync_asset_schedules

    asset = asset_factory(monitoring_enabled=True)
    sync_asset_schedules(db)
    claim_due_schedules(db)
    claim_due_schedules(db)

    checks = db.execute(
        select(Job).where(Job.kind == JobKind.SBOM_CHANGE_CHECK.value)
    ).scalars().all()
    assert len(checks) == 1
    assert checks[0].payload["asset_id"] == str(asset.id)
    assert checks[0].payload["trigger"] == "SCHEDULED"


def test_intel_sync_queues_a_reassessment(
    db: Session, asset_factory, settings
) -> None:
    asset = asset_factory()
    from app.modules.sbom import service

    service.store_sbom(
        db,
        asset_id=asset.id,
        scan_id=None,
        document=document([package("requests", "2.31.0")]),
        commit_sha="a" * 40,
    )
    db.commit()

    job = reassessment.enqueue_after_intel_sync(db, source="OSV", changed=7)
    assert job is not None
    assert job.kind == JobKind.SBOM_VULNERABILITY_REASSESSMENT.value
    assert job.payload["trigger"] == "INTEL_SYNC"
    assert reassessment.enqueue_after_intel_sync(db, source="OSV", changed=0) is None
    assert reassessment.enqueue_after_intel_sync(db, source="OSV", changed=5).id == job.id


def test_generation_job_failure_is_retried_not_lost(
    db: Session, asset_factory, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = asset_factory()
    workspace = write_tree(tmp_path / "repo", {"requirements.txt": "requests==2.31.0"})
    install_fake_checkout(monkeypatch, workspace)
    monkeypatch.setattr(
        lifecycle, "get_syft", lambda: FakeSyft(fail=ExternalServiceError("syft exploded"))
    )
    _make_job(db, JobKind.SBOM_GENERATE, {"asset_id": str(asset.id)})
    job = queue.claim_next(db, "worker-test")
    assert job is not None

    with pytest.raises(ExternalServiceError):
        worker._run_job(db, job, "worker-test")
    db.rollback()
    queue.mark_failed(db, job.id, "syft exploded")
    db.refresh(job)

    assert job.status == JobStatus.QUEUED.value
    assert job.attempts == 1
    run = db.execute(
        select(SbomMonitoringRun).where(SbomMonitoringRun.kind == "SBOM_GENERATION")
    ).scalar_one()
    assert run.status == "FAILED"
    assert db.execute(select(Sbom)).scalar_one_or_none() is None
    assert get_settings().job_max_attempts >= 1
