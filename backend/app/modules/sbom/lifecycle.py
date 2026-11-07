"""Continuous SBOM lifecycle: dependency checks, snapshot generation, status.

This module owns operation **B** (SBOM update) and the dependency-change half of
the continuous monitoring story. It deliberately shares everything it can with
the existing scan path:

* ``modules/scanners/syft.py`` generates the document — no second SBOM engine;
* ``modules/sbom/service.store_sbom`` persists it — one storage/metadata path;
* ``workers/checkout.py`` clones safely — one hardened checkout;
* ``workers/queue.py`` enqueues — the existing PostgreSQL queue;
* ``modules/sbom/diff.py`` compares inventories — one diff implementation.

The only operation that touches a repository is ``generate_snapshot``: an SBOM
cannot be generated without reading the tree. ``check_dependencies`` never
clones: it asks the provider for the head commit and the changed path list, and
falls back to ``git ls-remote`` (refs only). Reassessment lives in
``modules/vulnerabilities/reassessment.py`` and touches neither.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    DependencyChangeOutcome,
    JobKind,
    SbomFreshness,
    SbomMonitoringKind,
    SbomMonitoringStatus,
    SbomMonitoringTrigger,
    SbomSnapshotReason,
)
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.validators import validate_branch_name, validate_repository_url
from app.modules.assets.models import Asset
from app.modules.assets.service import resolve_access_token
from app.modules.findings.models import Finding
from app.modules.git_provider.client import (
    CommitComparison,
    GitProviderError,
    RepositoryProviderClient,
)
from app.modules.sbom import service as sbom_service
from app.modules.sbom.dependencies import (
    classify_paths,
    dependency_fingerprint,
    manifest_fingerprint,
)
from app.modules.sbom.diff import diff_packages
from app.modules.sbom.models import Sbom, SbomMonitoringRun, SbomPackage
from app.modules.scanners.registry import get_syft
from app.workers import queue
from app.workers.checkout import (
    cleanup_workspace,
    clone_repository,
    remote_head,
    workspace_for_sbom,
)
from app.workers.models import Job, Schedule

logger = get_logger(__name__)

#: Separate advisory-lock namespaces so a check and a generation for the same
#: repository do not block each other, while two generations cannot overlap.
LOCK_NAMESPACES = {"check": "check", "generate": "generate", "reassess": "reassess"}

#: A reassessment older than twice its schedule is reported as degraded.
DEGRADED_AFTER_INTERVALS = 2

DEPENDENCY_CHECK_SCHEDULE_PREFIX = "asset-sbom-check:"
REASSESSMENT_SCHEDULE_NAME = "sbom:reassess"


def _now() -> datetime:
    return datetime.now(UTC)


def _lock_key(namespace: str, asset_id: uuid.UUID) -> int:
    digest = hashlib.sha256(f"ai-native-security:{namespace}:{asset_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@contextmanager
def asset_operation_lock(
    db: Session, asset_id: uuid.UUID, namespace: str
) -> Iterator[bool]:
    """Try a PostgreSQL advisory lock scoped to (operation, asset).

    Advisory locks are session-scoped, so a crashed worker releases them with
    its connection — no stale row can block an asset forever.
    """
    if namespace not in LOCK_NAMESPACES:
        raise ValueError(f"Unknown lock namespace: {namespace}")
    key = _lock_key(namespace, asset_id)
    acquired = bool(
        db.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}).scalar()
    )
    try:
        yield acquired
    finally:
        if acquired:
            db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})


# ------------------------------------------------------------------ run records
def start_run(
    db: Session,
    *,
    asset_id: uuid.UUID,
    kind: str,
    trigger: str,
    sbom_id: uuid.UUID | None = None,
    job_id: uuid.UUID | None = None,
    branch: str | None = None,
    head_commit_sha: str | None = None,
    previous_commit_sha: str | None = None,
    dependency_fingerprint_value: str | None = None,
    previous_dependency_fingerprint: str | None = None,
) -> SbomMonitoringRun:
    """Create and commit a RUNNING monitoring row before doing any work.

    Committing first means a crash mid-operation leaves a RUNNING row that the
    next run can report, instead of losing the attempt in a rolled-back
    transaction.
    """
    run = SbomMonitoringRun(
        asset_id=asset_id,
        sbom_id=sbom_id,
        job_id=job_id,
        kind=kind,
        trigger=trigger,
        status=SbomMonitoringStatus.RUNNING.value,
        started_at=_now(),
        branch=branch,
        head_commit_sha=head_commit_sha,
        previous_commit_sha=previous_commit_sha,
        dependency_fingerprint=dependency_fingerprint_value,
        previous_dependency_fingerprint=previous_dependency_fingerprint,
        metrics={},
    )
    db.add(run)
    db.commit()
    return run


def finish_run(
    db: Session,
    run: SbomMonitoringRun,
    *,
    status: str,
    outcome: str | None = None,
    metrics: dict[str, Any] | None = None,
    error: str | None = None,
    skipped_reason: str | None = None,
    components_evaluated: int = 0,
    findings_created: int = 0,
    findings_updated: int = 0,
    findings_resolved: int = 0,
    new_kev_findings: int = 0,
    failure_count: int = 0,
    sbom_id: uuid.UUID | None = None,
    head_commit_sha: str | None = None,
) -> SbomMonitoringRun:
    finished = _now()
    run.status = status
    run.outcome = outcome
    run.finished_at = finished
    run.duration_ms = max(0, int((finished - run.started_at).total_seconds() * 1000))
    run.metrics = metrics or {}
    run.error_message = error[:4000] if error else None
    run.skipped_reason = skipped_reason[:255] if skipped_reason else None
    run.components_evaluated = components_evaluated
    run.findings_created = findings_created
    run.findings_updated = findings_updated
    run.findings_resolved = findings_resolved
    run.new_kev_findings = new_kev_findings
    run.failure_count = failure_count
    if sbom_id is not None:
        run.sbom_id = sbom_id
    if head_commit_sha:
        run.head_commit_sha = head_commit_sha
    db.commit()
    logger.info(
        "sbom monitoring run finished",
        extra={
            "extra_fields": {
                "run_id": str(run.id),
                "asset_id": str(run.asset_id),
                "kind": run.kind,
                "status": run.status,
                "outcome": run.outcome,
                "duration_ms": run.duration_ms,
                "components_evaluated": run.components_evaluated,
                "findings_created": run.findings_created,
                "findings_resolved": run.findings_resolved,
            }
        },
    )
    return run


def fail_run(db: Session, run_id: uuid.UUID, error: str) -> None:
    """Mark a committed run as FAILED after the caller rolled back."""
    db.rollback()
    run = db.get(SbomMonitoringRun, run_id)
    if run is None:  # pragma: no cover - defensive
        return
    finish_run(db, run, status=SbomMonitoringStatus.FAILED.value, error=error)


# ------------------------------------------------------------- head resolution
def resolve_head_commit(
    db: Session,
    asset: Asset,
    branch: str,
    *,
    client: RepositoryProviderClient | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Resolve the branch head without cloning.

    Returns ``(sha, source, error)``. The REST API is preferred because it also
    gives us the changed file list; ``git ls-remote`` is a refs-only fallback.
    Both failures are reported, never guessed around.
    """
    if not asset.repo_url:
        return None, None, "asset has no repository URL"
    token: str | None = None
    try:
        token = resolve_access_token(db, asset)
    except Exception:  # pragma: no cover - credential problems surface as UNKNOWN
        logger.warning(
            "repository credential could not be decrypted",
            extra={"extra_fields": {"asset_id": str(asset.id)}},
        )
    reference = validate_repository_url(asset.repo_url)
    provider_error: str | None = None
    try:
        sha = (client or RepositoryProviderClient()).head_commit(
            reference, branch, token=token
        )
        return sha, "provider_api", None
    except GitProviderError as exc:
        provider_error = exc.message
        logger.info(
            "provider head lookup failed; falling back to git ls-remote",
            extra={
                "extra_fields": {
                    "asset_id": str(asset.id),
                    "branch": branch,
                    "error": exc.message,
                }
            },
        )
    fallback_sha = remote_head(repo_url=asset.repo_url, branch=branch, token=token)
    if fallback_sha:
        return fallback_sha, "git_ls_remote", None
    return None, None, provider_error or "git ls-remote returned no ref"


def compare_commits(
    db: Session,
    asset: Asset,
    *,
    base_sha: str,
    head_sha: str,
    client: RepositoryProviderClient | None = None,
) -> CommitComparison | None:
    """Changed paths between two commits, or ``None`` when unknown."""
    if not asset.repo_url:
        return None
    token: str | None = None
    try:
        token = resolve_access_token(db, asset)
    except Exception:  # pragma: no cover - defensive
        token = None
    reference = validate_repository_url(asset.repo_url)
    try:
        return (client or RepositoryProviderClient()).compare(
            reference, base_sha, head_sha, token=token
        )
    except GitProviderError as exc:
        logger.warning(
            "commit comparison unavailable",
            extra={
                "extra_fields": {
                    "asset_id": str(asset.id),
                    "base": base_sha,
                    "head": head_sha,
                    "error": exc.message,
                }
            },
        )
        return None


# ---------------------------------------------------------------- change check
def check_dependencies(
    db: Session,
    *,
    asset_id: uuid.UUID,
    trigger: str = SbomMonitoringTrigger.SCHEDULED.value,
    branch: str | None = None,
    head_sha: str | None = None,
    changed_paths: Sequence[str] | None = None,
    job_id: uuid.UUID | None = None,
    client: RepositoryProviderClient | None = None,
) -> dict[str, Any]:
    """Decide whether software composition may have changed.

    Never clones and never runs a scanner. A commit change alone is not a
    dependency change: the changed paths decide, and when they cannot be
    obtained the answer is ``UNKNOWN`` — never "up to date".
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found", details={"asset_id": str(asset_id)})

    settings = get_settings()
    resolved_branch = validate_branch_name(branch or asset.default_branch)

    with asset_operation_lock(db, asset.id, "check") as acquired:
        if not acquired:
            logger.info(
                "dependency check skipped (lock held)",
                extra={"extra_fields": {"asset_id": str(asset.id)}},
            )
            return {
                "asset_id": str(asset.id),
                "outcome": "SKIPPED",
                "reason": "another dependency check is running",
            }

        snapshot = sbom_service.latest_sbom_for_asset(db, asset.id)
        run = start_run(
            db,
            asset_id=asset.id,
            kind=SbomMonitoringKind.DEPENDENCY_CHECK.value,
            trigger=trigger,
            job_id=job_id,
            branch=resolved_branch,
            previous_commit_sha=snapshot.commit_sha if snapshot else None,
        )
        run_id = run.id
        try:
            head: str | None
            head_source: str | None
            head_error: str | None
            if head_sha:
                head, head_source, head_error = head_sha[:64], "job_payload", None
            else:
                head, head_source, head_error = resolve_head_commit(
                    db, asset, resolved_branch, client=client
                )
            if not head:
                finish_run(
                    db,
                    run,
                    status=SbomMonitoringStatus.PARTIAL.value,
                    outcome=DependencyChangeOutcome.UNKNOWN.value,
                    error=head_error or "head commit could not be resolved",
                    metrics={"head_source": None},
                )
                return {
                    "asset_id": str(asset.id),
                    "outcome": DependencyChangeOutcome.UNKNOWN.value,
                    "run_id": str(run_id),
                    "error": head_error,
                }

            run.head_commit_sha = head
            metrics: dict[str, Any] = {"head_source": head_source}

            if snapshot is None:
                job, created = _enqueue_generation(
                    db,
                    asset_id=asset.id,
                    branch=resolved_branch,
                    head_sha=head,
                    reason=SbomSnapshotReason.INITIAL.value,
                    trigger=trigger,
                )
                metrics.update({"job_created": created, "job_id": str(job.id) if job else None})
                finish_run(
                    db,
                    run,
                    status=SbomMonitoringStatus.SUCCEEDED.value,
                    outcome=DependencyChangeOutcome.NO_SNAPSHOT.value,
                    metrics=metrics,
                    skipped_reason="no snapshot yet; initial generation queued",
                )
                return _check_result(asset.id, run, metrics)

            if snapshot.commit_sha and snapshot.commit_sha == head:
                finish_run(
                    db,
                    run,
                    status=SbomMonitoringStatus.SUCCEEDED.value,
                    outcome=DependencyChangeOutcome.UNCHANGED.value,
                    metrics=metrics,
                )
                return _check_result(asset.id, run, metrics)

            if not snapshot.commit_sha:
                # A snapshot from before commit tracking cannot be compared to
                # head. Claiming "no dependency change" would be a guess, so the
                # outcome is UNKNOWN and a fresh baseline is queued.
                job, created = _enqueue_generation(
                    db,
                    asset_id=asset.id,
                    branch=resolved_branch,
                    head_sha=head,
                    reason=SbomSnapshotReason.BASELINE.value,
                    trigger=trigger,
                )
                metrics.update(
                    {
                        "reason": "snapshot_commit_unknown",
                        "job_created": created,
                        "job_id": str(job.id) if job else None,
                    }
                )
                finish_run(
                    db,
                    run,
                    status=SbomMonitoringStatus.PARTIAL.value,
                    outcome=DependencyChangeOutcome.UNKNOWN.value,
                    metrics=metrics,
                    error=(
                        "the stored snapshot has no recorded commit; a baseline "
                        "generation was queued instead of claiming it is current"
                    ),
                )
                return _check_result(asset.id, run, metrics)

            if snapshot.branch and snapshot.branch != resolved_branch:
                # A different branch has a different composition; never reuse a
                # snapshot generated from another branch silently.
                job, created = _enqueue_generation(
                    db,
                    asset_id=asset.id,
                    branch=resolved_branch,
                    head_sha=head,
                    reason=SbomSnapshotReason.DEPENDENCY_CHANGE.value,
                    trigger=trigger,
                )
                metrics.update(
                    {
                        "reason": "branch_changed",
                        "snapshot_branch": snapshot.branch,
                        "job_created": created,
                        "job_id": str(job.id) if job else None,
                    }
                )
                finish_run(
                    db,
                    run,
                    status=SbomMonitoringStatus.SUCCEEDED.value,
                    outcome=DependencyChangeOutcome.DEPENDENCY_CHANGED.value,
                    metrics=metrics,
                )
                return _check_result(asset.id, run, metrics)

            if changed_paths is not None:
                paths = [str(path) for path in changed_paths]
                truncated = False
                metrics["changed_paths_source"] = "webhook"
            else:
                comparison = compare_commits(
                    db,
                    asset,
                    base_sha=snapshot.commit_sha,
                    head_sha=head,
                    client=client,
                )
                if comparison is None:
                    finish_run(
                        db,
                        run,
                        status=SbomMonitoringStatus.PARTIAL.value,
                        outcome=DependencyChangeOutcome.UNKNOWN.value,
                        error=(
                            "commit comparison unavailable; composition cannot be "
                            "determined and the snapshot is not claimed to be current"
                        ),
                        metrics=metrics,
                    )
                    return _check_result(asset.id, run, metrics)
                paths = comparison.files
                truncated = comparison.truncated
                metrics["changed_paths_source"] = "provider_compare"
                metrics["compare_truncated"] = truncated

            analysis = classify_paths(paths)
            metrics.update(
                {
                    "changed_paths_total": len(paths),
                    "changed_paths": paths[: settings.sbom_max_changed_paths],
                    "dependency_inputs": [entry.path for entry in analysis.dependency_files][
                        : settings.sbom_max_changed_paths
                    ],
                    "dependency_input_count": len(analysis.dependency_files),
                    "ecosystems": analysis.ecosystems,
                }
            )

            composition_changed = analysis.affects_composition or truncated
            if truncated:
                metrics["reason"] = "provider_truncated_path_list"

            if not composition_changed:
                finish_run(
                    db,
                    run,
                    status=SbomMonitoringStatus.SUCCEEDED.value,
                    outcome=DependencyChangeOutcome.NO_DEPENDENCY_CHANGE.value,
                    metrics=metrics,
                )
                return _check_result(asset.id, run, metrics)

            job, created = _enqueue_generation(
                db,
                asset_id=asset.id,
                branch=resolved_branch,
                head_sha=head,
                reason=SbomSnapshotReason.DEPENDENCY_CHANGE.value,
                trigger=trigger,
            )
            metrics.update({"job_created": created, "job_id": str(job.id) if job else None})
            finish_run(
                db,
                run,
                status=SbomMonitoringStatus.SUCCEEDED.value,
                outcome=DependencyChangeOutcome.DEPENDENCY_CHANGED.value,
                metrics=metrics,
            )
            return _check_result(asset.id, run, metrics)
        except Exception as exc:
            logger.exception(
                "dependency check failed",
                extra={"extra_fields": {"asset_id": str(asset.id)}},
            )
            fail_run(db, run_id, f"{exc.__class__.__name__}: {exc}")
            raise


def _check_result(asset_id: uuid.UUID, run: SbomMonitoringRun, metrics: dict[str, Any]) -> dict[str, Any]:
    return {
        "asset_id": str(asset_id),
        "run_id": str(run.id),
        "outcome": run.outcome,
        "status": run.status,
        "head_commit_sha": run.head_commit_sha,
        "dependency_inputs": metrics.get("dependency_inputs", []),
        "ecosystems": metrics.get("ecosystems", []),
        "job_id": metrics.get("job_id"),
        "duration_ms": run.duration_ms,
    }


def _enqueue_generation(
    db: Session,
    *,
    asset_id: uuid.UUID,
    branch: str,
    head_sha: str,
    reason: str,
    trigger: str,
) -> tuple[Job | None, bool]:
    payload = {
        "asset_id": str(asset_id),
        "branch": branch,
        "head_sha": head_sha,
        "reason": reason,
        "trigger": trigger,
    }
    return queue.enqueue_once(
        db,
        JobKind.SBOM_GENERATE,
        payload,
        match={"asset_id": str(asset_id), "head_sha": head_sha},
        priority=150,
    )


# ------------------------------------------------------------ snapshot creation
def generate_snapshot(
    db: Session,
    *,
    asset_id: uuid.UUID,
    trigger: str = SbomMonitoringTrigger.MANUAL.value,
    reason: str = SbomSnapshotReason.MANUAL.value,
    branch: str | None = None,
    head_sha: str | None = None,
    job_id: uuid.UUID | None = None,
    storage: Any | None = None,
    force: bool = False,
    heartbeat: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Checkout + Syft only. Never runs Trivy, Semgrep or Gitleaks.

    A snapshot is immutable: a new row is added and the previous one is linked,
    never updated. When the resolved inventory and commit are identical to the
    latest snapshot the generation is skipped (``force`` is reserved for
    regeneration after a storage incident and is not exposed through the API).
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found", details={"asset_id": str(asset_id)})
    if not asset.repo_url:
        raise ValidationError("Asset has no repository URL")
    settings = get_settings()
    resolved_branch = validate_branch_name(branch or asset.default_branch)

    with asset_operation_lock(db, asset.id, "generate") as acquired:
        if not acquired:
            logger.info(
                "sbom generation skipped (lock held)",
                extra={"extra_fields": {"asset_id": str(asset.id)}},
            )
            return {
                "asset_id": str(asset.id),
                "status": "SKIPPED",
                "reason": "another sbom generation is running",
            }

        latest = sbom_service.latest_sbom_for_asset(db, asset.id)
        run = start_run(
            db,
            asset_id=asset.id,
            kind=SbomMonitoringKind.SBOM_GENERATION.value,
            trigger=trigger,
            job_id=job_id,
            branch=resolved_branch,
            head_commit_sha=head_sha,
            previous_commit_sha=latest.commit_sha if latest else None,
            previous_dependency_fingerprint=(
                latest.dependency_fingerprint if latest else None
            ),
        )
        run_id = run.id
        workspace = None
        beat = heartbeat or (lambda: None)
        try:
            workspace = workspace_for_sbom(uuid.uuid4())
            token = resolve_access_token(db, asset)
            # Cloning a large repository can outlast the stale-job window; the
            # heartbeat keeps the job from being reaped while it is still alive.
            beat()
            checkout = clone_repository(
                repo_url=asset.repo_url,
                branch=resolved_branch,
                token=token,
                destination=workspace,
            )
            beat()
            document = get_syft().generate(
                workspace,
                workspace.parent / f"sbom-{run_id}-reports",
                sbom_format=settings.sbom_format,
            )
            beat()
            manifests = manifest_fingerprint(
                workspace,
                max_files=settings.sbom_max_manifest_files,
                max_bytes=settings.sbom_max_manifest_bytes,
            )
            new_fingerprint = dependency_fingerprint(document.packages)

            identical = (
                latest is not None
                and not force
                and latest.dependency_fingerprint is not None
                and latest.dependency_fingerprint == new_fingerprint
                and latest.commit_sha == checkout.commit_sha
            )
            if identical:
                finish_run(
                    db,
                    run,
                    status=SbomMonitoringStatus.SKIPPED.value,
                    metrics={
                        "reason": "identical_inventory",
                        "dependency_fingerprint": new_fingerprint,
                        "commit_sha": checkout.commit_sha,
                        "packages": len(document.packages),
                        "manifest_files": manifests.files,
                    },
                    skipped_reason="inventory and commit match the latest snapshot",
                    sbom_id=latest.id if latest else None,
                )
                logger.info(
                    "sbom generation skipped (unchanged inventory)",
                    extra={
                        "extra_fields": {
                            "asset_id": str(asset.id),
                            "dependency_fingerprint": new_fingerprint,
                        }
                    },
                )
                return {
                    "asset_id": str(asset.id),
                    "status": "SKIPPED",
                    "reason": "identical_inventory",
                    "snapshot_id": str(latest.id) if latest else None,
                }

            snapshot = sbom_service.store_sbom(
                db,
                asset_id=asset.id,
                scan_id=None,
                document=document,
                storage=storage,
                commit_sha=checkout.commit_sha,
                branch=checkout.branch,
                creation_reason=reason,
                manifest_fingerprint=manifests.fingerprint,
                dependency_fingerprint=new_fingerprint,
                previous_snapshot_id=latest.id if latest else None,
                generated_at=_now(),
            )
            previous_packages = (
                sbom_service.packages_for_sbom(db, latest.id) if latest else []
            )
            diff = diff_packages(
                previous_packages,
                document.packages,
                previous_sbom_id=str(latest.id) if latest else None,
                current_sbom_id=str(snapshot.id),
            )
            metrics = {
                "packages": snapshot.package_count,
                "direct_packages": snapshot.direct_package_count,
                "transitive_packages": snapshot.transitive_package_count,
                "manifest_files": manifests.files,
                "manifest_files_truncated": manifests.truncated,
                "dependency_fingerprint": new_fingerprint,
                "previous_dependency_fingerprint": (
                    latest.dependency_fingerprint if latest else None
                ),
                "commit_sha": checkout.commit_sha,
                "diff": diff.counts(),
                "tool_version": document.tool_version,
            }
            run.dependency_fingerprint = new_fingerprint
            db.flush()

            job, created = queue.enqueue_once(
                db,
                JobKind.SBOM_VULNERABILITY_REASSESSMENT,
                {
                    "asset_id": str(asset.id),
                    "sbom_id": str(snapshot.id),
                    "trigger": SbomMonitoringTrigger.SBOM_UPDATE.value,
                },
                match={"sbom_id": str(snapshot.id)},
                priority=200,
            )
            metrics["reassessment_job_id"] = str(job.id) if job else None
            metrics["reassessment_job_created"] = created

            finish_run(
                db,
                run,
                status=SbomMonitoringStatus.SUCCEEDED.value,
                metrics=metrics,
                sbom_id=snapshot.id,
                head_commit_sha=checkout.commit_sha,
            )
            logger.info(
                "sbom snapshot generated",
                extra={
                    "extra_fields": {
                        "asset_id": str(asset.id),
                        "sbom_id": str(snapshot.id),
                        "reason": reason,
                        "packages": snapshot.package_count,
                        "added": diff.added,
                        "removed": diff.removed,
                        "version_changed": diff.version_changed,
                    }
                },
            )
            return {
                "asset_id": str(asset.id),
                "status": "SUCCEEDED",
                "snapshot_id": str(snapshot.id),
                "commit_sha": checkout.commit_sha,
                "packages": snapshot.package_count,
                "diff": diff.counts(),
            }
        except IntegrityError:
            # Concurrent generation of the same (asset, fingerprint, commit):
            # the unique index won the race and the row already exists.
            db.rollback()
            existing = _snapshot_for_commit(db, asset.id)
            existing_run = db.get(SbomMonitoringRun, run_id)
            if existing_run is not None:
                finish_run(
                    db,
                    existing_run,
                    status=SbomMonitoringStatus.SKIPPED.value,
                    metrics={"reason": "duplicate_snapshot"},
                    skipped_reason="an identical snapshot was created concurrently",
                    sbom_id=existing.id if existing else None,
                )
            return {
                "asset_id": str(asset.id),
                "status": "SKIPPED",
                "reason": "duplicate_snapshot",
                "snapshot_id": str(existing.id) if existing else None,
            }
        except Exception as exc:
            logger.exception(
                "sbom generation failed",
                extra={"extra_fields": {"asset_id": str(asset.id)}},
            )
            fail_run(db, run_id, f"{exc.__class__.__name__}: {exc}")
            raise
        finally:
            cleanup_workspace(workspace)


def _snapshot_for_commit(db: Session, asset_id: uuid.UUID) -> Sbom | None:
    return sbom_service.latest_sbom_for_asset(db, asset_id)


# ----------------------------------------------------------------- status views
def _latest_run(db: Session, asset_id: uuid.UUID, kind: str) -> SbomMonitoringRun | None:
    return db.execute(
        select(SbomMonitoringRun)
        .where(SbomMonitoringRun.asset_id == asset_id, SbomMonitoringRun.kind == kind)
        .order_by(SbomMonitoringRun.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _active_job(db: Session, kind: JobKind, asset_id: uuid.UUID) -> Job | None:
    return queue.find_active(db, kind, {"asset_id": str(asset_id)})


def _next_run_at(db: Session, name: str) -> datetime | None:
    schedule = db.execute(select(Schedule).where(Schedule.name == name)).scalar_one_or_none()
    if schedule is None or not schedule.enabled:
        return None
    return schedule.next_run_at


def _vulnerable_component_count(db: Session, snapshot: Sbom | None) -> int:
    if snapshot is None:
        return 0
    rows = db.execute(
        select(func.count(func.distinct(func.lower(Finding.package_name))))
        .select_from(Finding)
        .join(
            SbomPackage,
            (func.lower(Finding.package_name) == func.lower(SbomPackage.name))
            & (Finding.package_version == SbomPackage.version),
        )
        .where(
            Finding.asset_id == snapshot.asset_id,
            Finding.status.in_(ACTIVE_FINDING_STATUSES),
            Finding.scanner == "osv",
            SbomPackage.sbom_id == snapshot.id,
        )
    ).scalar_one()
    return int(rows)


def freshness_for(
    db: Session,
    asset: Asset,
    snapshot: Sbom | None,
    *,
    check: SbomMonitoringRun | None,
    generation: SbomMonitoringRun | None,
    pending_check: bool,
    pending_generation: bool,
) -> tuple[str, str]:
    """Return ``(freshness, detail)`` with an explicit reason for UNKNOWN."""
    if snapshot is None:
        if pending_generation or pending_check:
            return SbomFreshness.PENDING.value, "initial snapshot is being generated"
        return SbomFreshness.MISSING.value, "no SBOM snapshot has been generated yet"

    if pending_generation:
        return SbomFreshness.PENDING.value, "a new snapshot is being generated"

    if not snapshot.commit_sha:
        # Composition can only be verified against a commit. A snapshot that
        # predates commit tracking is reported as unverified, whatever a check
        # recorded before this rule existed.
        return (
            SbomFreshness.UNKNOWN.value,
            "the stored snapshot has no recorded commit, so its composition cannot "
            "be verified against the repository head",
        )

    snapshot_at = snapshot.generated_at or snapshot.created_at
    newer_check = check is not None and check.started_at >= snapshot_at
    newer_generation = generation is not None and generation.started_at >= snapshot_at

    if newer_generation and generation is not None:
        if generation.status == SbomMonitoringStatus.FAILED.value:
            return (
                SbomFreshness.FAILED.value,
                f"the last snapshot generation failed: {generation.error_message or 'unknown error'}",
            )
        if (
            generation.status == SbomMonitoringStatus.SUCCEEDED.value
            and generation.sbom_id == snapshot.id
        ):
            return (
                SbomFreshness.CURRENT.value,
                "the snapshot was generated after the last detected change",
            )

    if newer_check and check is not None:
        if check.outcome in {
            DependencyChangeOutcome.UNCHANGED.value,
            DependencyChangeOutcome.NO_DEPENDENCY_CHANGE.value,
        }:
            return (
                SbomFreshness.CURRENT.value,
                "the last dependency check found no composition change",
            )
        if check.outcome == DependencyChangeOutcome.DEPENDENCY_CHANGED.value:
            if pending_generation:
                return SbomFreshness.PENDING.value, "a dependency change is being applied"
            if (
                newer_generation
                and generation is not None
                and generation.status == SbomMonitoringStatus.FAILED.value
            ):
                return (
                    SbomFreshness.FAILED.value,
                    f"dependency change detected but snapshot generation failed: "
                    f"{generation.error_message or 'unknown error'}",
                )
            return (
                SbomFreshness.STALE.value,
                "dependency inputs changed since this snapshot was generated",
            )
        if check.outcome == DependencyChangeOutcome.NO_SNAPSHOT.value:
            return SbomFreshness.PENDING.value, "the initial snapshot is queued"
        if check.status in {
            SbomMonitoringStatus.FAILED.value,
            SbomMonitoringStatus.PARTIAL.value,
        }:
            return (
                SbomFreshness.UNKNOWN.value,
                f"the last dependency check could not verify composition: "
                f"{check.error_message or check.outcome or 'unknown reason'}",
            )

    if check is None:
        return (
            SbomFreshness.UNKNOWN.value,
            "no dependency check has run since this snapshot was generated",
        )
    return (
        SbomFreshness.UNKNOWN.value,
        f"last dependency check outcome was {check.outcome or check.status}",
    )


def asset_monitoring_status(db: Session, asset_id: uuid.UUID) -> dict[str, Any]:
    """Everything the SBOM overview and monitoring panel need, in one round trip."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found", details={"asset_id": str(asset_id)})
    settings = get_settings()
    snapshot = sbom_service.latest_sbom_for_asset(db, asset.id)
    check = _latest_run(db, asset.id, SbomMonitoringKind.DEPENDENCY_CHECK.value)
    generation = _latest_run(db, asset.id, SbomMonitoringKind.SBOM_GENERATION.value)
    reassessment = _latest_run(
        db, asset.id, SbomMonitoringKind.VULNERABILITY_REASSESSMENT.value
    )
    pending_check = _active_job(db, JobKind.SBOM_CHANGE_CHECK, asset.id) is not None
    pending_generation = _active_job(db, JobKind.SBOM_GENERATE, asset.id) is not None
    pending_reassessment = (
        _active_job(db, JobKind.SBOM_VULNERABILITY_REASSESSMENT, asset.id) is not None
    )

    freshness, freshness_detail = freshness_for(
        db,
        asset,
        snapshot,
        check=check,
        generation=generation,
        pending_check=pending_check,
        pending_generation=pending_generation,
    )

    now = _now()
    failed_evaluations = int(
        db.execute(
            select(func.count(SbomMonitoringRun.id)).where(
                SbomMonitoringRun.asset_id == asset.id,
                SbomMonitoringRun.kind
                == SbomMonitoringKind.VULNERABILITY_REASSESSMENT.value,
                SbomMonitoringRun.status.in_(
                    [SbomMonitoringStatus.FAILED.value, SbomMonitoringStatus.PARTIAL.value]
                ),
                SbomMonitoringRun.started_at >= now - timedelta(days=7),
            )
        ).scalar_one()
    )

    monitoring = "DISABLED"
    if settings.sbom_monitoring_enabled:
        last = reassessment
        overdue = bool(
            last is not None
            and last.finished_at is not None
            and last.finished_at
            < now - timedelta(minutes=settings.sbom_reassessment_interval_minutes * DEGRADED_AFTER_INTERVALS)
        )
        if last is None:
            monitoring = "UNKNOWN"
        elif last.status == SbomMonitoringStatus.RUNNING.value:
            monitoring = "RUNNING"
        elif last.status in {
            SbomMonitoringStatus.FAILED.value,
            SbomMonitoringStatus.PARTIAL.value,
        } or overdue or last.finished_at is None:
            monitoring = "DEGRADED"
        else:
            monitoring = "HEALTHY"

    return {
        "asset_id": str(asset.id),
        "monitoring_enabled": asset.monitoring_enabled,
        "sbom_monitoring_enabled": settings.sbom_monitoring_enabled,
        "monitoring_status": monitoring,
        "freshness": freshness,
        "freshness_detail": freshness_detail,
        "latest_snapshot": _snapshot_payload(snapshot),
        "vulnerable_components": _vulnerable_component_count(db, snapshot),
        "pending": {
            "dependency_check": pending_check,
            "sbom_generation": pending_generation,
            "reassessment": pending_reassessment,
            # A change was detected and the snapshot does not reflect it yet.
            "dependency_change_pending": bool(
                check
                and check.outcome == DependencyChangeOutcome.DEPENDENCY_CHANGED.value
                and snapshot is not None
                and check.started_at >= (snapshot.generated_at or snapshot.created_at)
            ),
        },
        "last_dependency_check": _run_payload(check),
        "last_generation": _run_payload(generation),
        "last_reassessment": _run_payload(reassessment),
        "next_dependency_check": _next_run_at(
            db, f"{DEPENDENCY_CHECK_SCHEDULE_PREFIX}{asset.id}"
        ),
        "next_reassessment": _next_run_at(db, REASSESSMENT_SCHEDULE_NAME),
        "failed_evaluations_7d": failed_evaluations,
        "new_findings_since_last_evaluation": (
            reassessment.findings_created if reassessment else 0
        ),
        "new_kev_since_last_evaluation": (
            reassessment.new_kev_findings if reassessment else 0
        ),
    }


def _snapshot_payload(snapshot: Sbom | None) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    return {
        "id": str(snapshot.id),
        "created_at": snapshot.created_at.isoformat() if snapshot.created_at else None,
        "generated_at": snapshot.generated_at.isoformat() if snapshot.generated_at else None,
        "commit_sha": snapshot.commit_sha,
        "branch": snapshot.branch,
        "dependency_fingerprint": snapshot.dependency_fingerprint,
        "manifest_fingerprint": snapshot.manifest_fingerprint,
        "artifact_digest": snapshot.artifact_digest,
        "sha256": snapshot.sha256,
        "creation_reason": snapshot.creation_reason,
        "generation_status": snapshot.generation_status,
        "package_count": snapshot.package_count,
        "direct_package_count": snapshot.direct_package_count,
        "transitive_package_count": snapshot.transitive_package_count,
        "previous_snapshot_id": (
            str(snapshot.previous_snapshot_id) if snapshot.previous_snapshot_id else None
        ),
        "size_bytes": snapshot.size_bytes,
        "format": snapshot.format,
    }


def _run_payload(run: SbomMonitoringRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    return {
        "id": str(run.id),
        "kind": run.kind,
        "status": run.status,
        "outcome": run.outcome,
        "trigger": run.trigger,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "duration_ms": run.duration_ms,
        "head_commit_sha": run.head_commit_sha,
        "previous_commit_sha": run.previous_commit_sha,
        "components_evaluated": run.components_evaluated,
        "findings_created": run.findings_created,
        "findings_updated": run.findings_updated,
        "findings_resolved": run.findings_resolved,
        "new_kev_findings": run.new_kev_findings,
        "failure_count": run.failure_count,
        "skipped_reason": run.skipped_reason,
        "error_message": run.error_message,
        "metrics": run.metrics or {},
    }


# -------------------------------------------------------------------- summary
def monitoring_summary(db: Session, *, days: int = 30) -> dict[str, Any]:
    """Operational counters derived from executed runs — never estimated silently.

    ``estimated_full_scans_avoided`` is an explicit estimate: it counts
    dependency checks that proved composition unchanged, each of which would
    otherwise have required the periodic full scan it replaced. The raw counts
    it is derived from are returned alongside it.
    """
    settings = get_settings()
    since = _now() - timedelta(days=days)
    rows = db.execute(
        select(SbomMonitoringRun).where(SbomMonitoringRun.started_at >= since)
    ).scalars().all()

    def _of(kind: str, status: str | None = None) -> list[SbomMonitoringRun]:
        return [
            run
            for run in rows
            if run.kind == kind and (status is None or run.status == status)
        ]

    checks = _of(SbomMonitoringKind.DEPENDENCY_CHECK.value)
    generations = _of(SbomMonitoringKind.SBOM_GENERATION.value)
    reassessments = _of(SbomMonitoringKind.VULNERABILITY_REASSESSMENT.value)

    unchanged_checks = [
        run
        for run in checks
        if run.outcome
        in {
            DependencyChangeOutcome.UNCHANGED.value,
            DependencyChangeOutcome.NO_DEPENDENCY_CHANGE.value,
        }
    ]
    changed_checks = [
        run for run in checks if run.outcome == DependencyChangeOutcome.DEPENDENCY_CHANGED.value
    ]
    unknown_checks = [
        run
        for run in checks
        if run.outcome
        in {DependencyChangeOutcome.UNKNOWN.value, DependencyChangeOutcome.FAILED.value}
    ]
    skipped_generations = [
        run for run in generations if run.status == SbomMonitoringStatus.SKIPPED.value
    ]

    def _avg_duration(items: list[SbomMonitoringRun]) -> float | None:
        values = [run.duration_ms for run in items if run.duration_ms is not None]
        return round(sum(values) / len(values), 1) if values else None

    scanner_count = len([name for name in settings.scanners_enabled if name != "syft"])
    avoided = len(unchanged_checks)
    return {
        "window_days": days,
        "dependency_checks": len(checks),
        "dependency_changes_detected": len(changed_checks),
        "dependency_checks_unchanged": len(unchanged_checks),
        "dependency_checks_unknown": len(unknown_checks),
        "sbom_generations": len(
            [run for run in generations if run.status == SbomMonitoringStatus.SUCCEEDED.value]
        ),
        "sbom_generations_skipped_unchanged": len(skipped_generations),
        "reassessments": len(reassessments),
        "reassessment_failures": len(
            [
                run
                for run in reassessments
                if run.status
                in {SbomMonitoringStatus.FAILED.value, SbomMonitoringStatus.PARTIAL.value}
            ]
        ),
        "components_evaluated": sum(run.components_evaluated for run in reassessments),
        "findings_created": sum(run.findings_created for run in reassessments),
        "findings_updated": sum(run.findings_updated for run in reassessments),
        "findings_resolved": sum(run.findings_resolved for run in reassessments),
        # Reopenings are counted explicitly: a resolution that a later, better
        # evidence pass reverses must not look like a silent disappearance.
        "findings_reopened": sum(
            int((run.metrics or {}).get("reopened", 0) or 0) for run in reassessments
        ),
        "new_kev_findings": sum(run.new_kev_findings for run in reassessments),
        "avg_dependency_check_ms": _avg_duration(checks),
        "avg_generation_ms": _avg_duration(generations),
        "avg_reassessment_ms": _avg_duration(reassessments),
        # Estimates, clearly labelled, derived from the counts above.
        "estimated_full_scans_avoided": avoided,
        "estimated_repository_checkouts_avoided": avoided,
        "estimated_scanner_executions_avoided": avoided * scanner_count,
        "estimate_basis": (
            "each dependency check that proved composition unchanged replaced the "
            "periodic full scan (clone + scanners) it would otherwise have required"
        ),
    }


def enqueue_check(
    db: Session,
    asset: Asset,
    *,
    trigger: str = SbomMonitoringTrigger.MANUAL.value,
    branch: str | None = None,
    head_sha: str | None = None,
    changed_paths: Sequence[str] | None = None,
) -> tuple[Job | None, bool]:
    payload: dict[str, Any] = {
        "asset_id": str(asset.id),
        "trigger": trigger,
        "branch": branch or asset.default_branch,
    }
    if head_sha:
        payload["head_sha"] = head_sha[:64]
    if changed_paths is not None:
        payload["changed_paths"] = [str(path) for path in changed_paths][:1000]
    return queue.enqueue_once(
        db,
        JobKind.SBOM_CHANGE_CHECK,
        payload,
        match={"asset_id": str(asset.id)},
        priority=150,
    )


def enqueue_generation(
    db: Session,
    asset: Asset,
    *,
    trigger: str = SbomMonitoringTrigger.MANUAL.value,
    branch: str | None = None,
) -> tuple[Job | None, bool]:
    return queue.enqueue_once(
        db,
        JobKind.SBOM_GENERATE,
        {
            "asset_id": str(asset.id),
            "branch": branch or asset.default_branch,
            "reason": SbomSnapshotReason.MANUAL.value,
            "trigger": trigger,
        },
        match={"asset_id": str(asset.id)},
        priority=150,
    )


def enqueue_reassessment(
    db: Session,
    asset: Asset,
    *,
    sbom_id: uuid.UUID | None = None,
    trigger: str = SbomMonitoringTrigger.MANUAL.value,
) -> tuple[Job | None, bool]:
    match: dict[str, str] = {"asset_id": str(asset.id)}
    payload: dict[str, Any] = {"asset_id": str(asset.id), "trigger": trigger}
    if sbom_id is not None:
        payload["sbom_id"] = str(sbom_id)
        match["sbom_id"] = str(sbom_id)
    return queue.enqueue_once(
        db,
        JobKind.SBOM_VULNERABILITY_REASSESSMENT,
        payload,
        match=match,
        priority=220,
    )


def require_asset(db: Session, asset_id: uuid.UUID) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found", details={"asset_id": str(asset_id)})
    return asset


def validate_snapshot_belongs(db: Session, asset_id: uuid.UUID, sbom_id: uuid.UUID) -> Sbom:
    snapshot = db.get(Sbom, sbom_id)
    if snapshot is None or snapshot.asset_id != asset_id:
        raise ValidationError(
            "SBOM snapshot does not belong to this asset",
            details={"asset_id": str(asset_id), "sbom_id": str(sbom_id)},
        )
    return snapshot
