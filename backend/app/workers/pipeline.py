"""Scan pipeline executed by the worker process.

Order: checkout -> Syft SBOM -> Trivy/Semgrep/Gitleaks -> normalize ->
correlate with OSV/KEV -> persist findings -> evaluate disappeared findings ->
summary. The API is never blocked: all of this runs outside the request path.

Resolution semantics: findings are only auto-resolved when the scan completed
successfully (no scanner failed or timed out), and only for scanners that
actually produced a successful run.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    ScannerExecutionStatus,
    ScanStatus,
    Severity,
)
from app.core.logging import get_logger
from app.modules.assets.models import Asset
from app.modules.assets.service import resolve_access_token
from app.modules.findings import service as findings_service
from app.modules.sbom.service import store_sbom
from app.modules.scanners.base import NormalizedFinding
from app.modules.scanners.registry import enabled_scanners, get_syft
from app.modules.scans.models import Scan, ScannerExecution
from app.modules.vulnerabilities.correlation import correlate_packages, enrich_scan_findings
from app.workers.checkout import Checkout, cleanup_workspace, clone_repository, workspace_for_scan

logger = get_logger(__name__)

Heartbeat = Callable[[], None]


class ScanAborted(Exception):
    """Raised internally when a scan was canceled mid-flight."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _noop() -> None:
    return None


def _refresh_status(db: Session, scan_id: uuid.UUID) -> str:
    db.refresh(db.get(Scan, scan_id))
    scan = db.get(Scan, scan_id)
    return scan.status if scan else ScanStatus.FAILED.value


def _ensure_active(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ScanAborted(f"scan {scan_id} no longer exists")
    if scan.status == ScanStatus.CANCELED.value:
        raise ScanAborted("scan canceled")
    return scan


def execute_scan(db: Session, scan_id: uuid.UUID, heartbeat: Heartbeat | None = None) -> None:
    """Run one scan to completion, recording every stage in PostgreSQL."""
    heartbeat = heartbeat or _noop
    scan = db.get(Scan, scan_id)
    if scan is None:
        logger.warning("scan not found", extra={"extra_fields": {"scan_id": str(scan_id)}})
        return
    if scan.status not in {ScanStatus.PENDING.value, ScanStatus.RUNNING.value}:
        logger.info(
            "scan skipped (not pending)",
            extra={"extra_fields": {"scan_id": str(scan_id), "status": scan.status}},
        )
        return

    asset = db.get(Asset, scan.asset_id)
    if asset is None:
        _fail(db, scan, "Asset no longer exists")
        return

    settings = get_settings()
    workspace: Path | None = None
    scan.status = ScanStatus.RUNNING.value
    scan.started_at = scan.started_at or _utcnow()
    scan.error_message = None
    asset.last_scan_status = ScanStatus.RUNNING.value
    db.commit()

    findings: list[NormalizedFinding] = []
    successful_scanners: list[str] = []
    failed_scanners: list[str] = []
    new_findings = 0
    resolved = 0
    packages = []

    try:
        heartbeat()
        workspace = workspace_for_scan(scan.id)
        checkout = _checkout(db, scan, asset, workspace, heartbeat)

        scan.commit_sha = checkout.commit_sha
        scan.branch = checkout.branch
        asset.last_scan_at = _utcnow()
        db.commit()

        # ------------------------------------------------------------ SBOM
        try:
            sbom_document = get_syft().generate(workspace, workspace.parent / f"scan-{scan.id}-reports")
            _record_execution(
                db,
                scan=scan,
                scanner="syft",
                status=ScannerExecutionStatus.SUCCESS.value,
                version=sbom_document.tool_version,
                result_count=len(sbom_document.packages),
            )
            store_sbom(db, asset_id=asset.id, scan_id=scan.id, document=sbom_document)
            packages = sbom_document.packages
            db.commit()
        except Exception as exc:
            logger.exception("sbom generation failed", extra={"extra_fields": {"scan_id": str(scan.id)}})
            _record_execution(
                db,
                scan=scan,
                scanner="syft",
                status=ScannerExecutionStatus.FAILED.value,
                error_message=str(exc)[:2000],
            )
            db.commit()
            raise RuntimeError(f"SBOM generation failed: {exc}") from exc

        # --------------------------------------------------------- scanners
        report_dir = settings.workspace_root / f"scan-{scan.id}-reports"
        for scanner in enabled_scanners():
            _ensure_active(db, scan.id)
            heartbeat()
            execution = _record_execution(
                db,
                scan=scan,
                scanner=scanner.name,
                status=ScannerExecutionStatus.RUNNING.value,
                version=None,
                started_at=_utcnow(),
            )
            db.commit()

            run = scanner.run(workspace, report_dir)
            execution.status = run.status
            execution.version = run.version
            execution.exit_code = run.exit_code
            execution.duration_seconds = int(run.duration_seconds)
            execution.finished_at = _utcnow()
            execution.result_count = len(run.findings)
            execution.command = run.command
            execution.stdout_excerpt = run.stdout_excerpt
            execution.stderr_excerpt = run.stderr_excerpt
            execution.error_message = run.error_message
            db.commit()

            if run.status == ScannerExecutionStatus.SUCCESS.value:
                findings.extend(run.findings)
                successful_scanners.append(scanner.name)
            else:
                failed_scanners.append(scanner.name)

        # ------------------------------------------------- finding pipeline
        _ensure_active(db, scan.id)
        heartbeat()
        counts = findings_service.record_scan_findings(
            db, asset_id=asset.id, scan_id=scan.id, normalized=findings
        )
        new_findings = counts["created"]

        correlation = correlate_packages(db, asset_id=asset.id, packages=packages)
        if correlation:
            correlation_counts = findings_service.record_scan_findings(
                db, asset_id=asset.id, scan_id=scan.id, normalized=correlation
            )
            new_findings += correlation_counts["created"]
        db.commit()

        heartbeat()
        enrich_scan_findings(db, scan.id)
        db.commit()

        # --------------------------------------------------------- summary
        summary = findings_service.scan_summary(db, scan.id)
        scan.total_findings = summary["total"]
        scan.critical_count = summary.get(Severity.CRITICAL.value, 0)
        scan.high_count = summary.get(Severity.HIGH.value, 0)
        scan.medium_count = summary.get(Severity.MEDIUM.value, 0)
        scan.low_count = summary.get(Severity.LOW.value, 0)
        scan.info_count = summary.get(Severity.INFO.value, 0)
        scan.unknown_count = summary.get(Severity.UNKNOWN.value, 0)
        scan.new_findings = new_findings

        if failed_scanners:
            scan.status = ScanStatus.FAILED.value
            scan.error_message = (
                "Scanner failure: " + ", ".join(sorted(failed_scanners))
                + ". Findings were recorded but no findings were auto-resolved."
            )
        else:
            resolved = findings_service.resolve_missing_findings(
                db,
                asset_id=asset.id,
                scan_id=scan.id,
                scanners=[*successful_scanners, "osv"],
            )
            scan.status = ScanStatus.COMPLETED.value
        scan.resolved_findings = resolved

    except ScanAborted as exc:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is not None and scan.status != ScanStatus.CANCELED.value:
            scan.status = ScanStatus.CANCELED.value
            scan.error_message = str(exc)
        logger.info("scan aborted", extra={"extra_fields": {"scan_id": str(scan_id), "reason": str(exc)}})
        db.commit()
        return
    except Exception as exc:
        db.rollback()
        logger.exception("scan failed", extra={"extra_fields": {"scan_id": str(scan_id)}})
        current = db.get(Scan, scan_id)
        if current is not None:
            _fail(db, current, _describe(exc))
            db.commit()
        return
    finally:
        cleanup_workspace(workspace)
        _cleanup_reports(settings.workspace_root / f"scan-{scan_id}-reports")

    # Persist the outcome computed inside the try block before refreshing:
    # refresh() would otherwise discard uncommitted changes.
    db.commit()
    db.refresh(scan)
    finished = _utcnow()
    scan.finished_at = finished
    if scan.started_at:
        scan.duration_seconds = int((finished - scan.started_at).total_seconds())
    asset = db.get(Asset, scan.asset_id)
    if asset is not None:
        asset.last_scan_status = scan.status
        asset.last_scan_at = finished
    db.commit()
    logger.info(
        "scan finished",
        extra={
            "extra_fields": {
                "scan_id": str(scan.id),
                "status": scan.status,
                "total_findings": scan.total_findings,
                "new_findings": scan.new_findings,
                "resolved_findings": scan.resolved_findings,
                "duration_seconds": scan.duration_seconds,
                "scanners_ok": successful_scanners,
                "scanners_failed": failed_scanners,
            }
        },
    )


def _checkout(
    db: Session, scan: Scan, asset: Asset, workspace: Path, heartbeat: Heartbeat
) -> Checkout:
    token = resolve_access_token(db, asset)
    heartbeat()
    return clone_repository(
        repo_url=asset.repo_url,
        branch=scan.branch or asset.default_branch,
        token=token,
        destination=workspace,
    )


def _record_execution(
    db: Session,
    *,
    scan: Scan,
    scanner: str,
    status: str,
    version: str | None = None,
    started_at: datetime | None = None,
    result_count: int = 0,
    error_message: str | None = None,
) -> ScannerExecution:
    execution = db.execute(
        select(ScannerExecution).where(
            ScannerExecution.scan_id == scan.id, ScannerExecution.scanner == scanner
        )
    ).scalar_one_or_none()
    if execution is None:
        execution = ScannerExecution(
            scan_id=scan.id,
            scanner=scanner,
            status=status,
            version=version,
            started_at=started_at or _utcnow(),
            result_count=result_count,
            error_message=error_message,
        )
        db.add(execution)
    else:
        execution.status = status
        execution.version = version or execution.version
        execution.result_count = result_count
        execution.error_message = error_message
        if status in {
            ScannerExecutionStatus.SUCCESS.value,
            ScannerExecutionStatus.FAILED.value,
            ScannerExecutionStatus.TIMED_OUT.value,
            ScannerExecutionStatus.SKIPPED.value,
        }:
            execution.finished_at = _utcnow()
            if execution.started_at:
                execution.duration_seconds = int(
                    (execution.finished_at - execution.started_at).total_seconds()
                )
    db.flush()
    return execution


def _fail(db: Session, scan: Scan, message: str) -> None:
    scan.status = ScanStatus.FAILED.value
    scan.error_message = message[:4000]
    scan.finished_at = _utcnow()
    if scan.started_at:
        scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds())
    asset = db.get(Asset, scan.asset_id)
    if asset is not None:
        asset.last_scan_status = ScanStatus.FAILED.value
        asset.last_scan_at = scan.finished_at
    db.commit()


def _cleanup_reports(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _describe(exc: Exception) -> str:
    from app.core.errors import AppError

    if isinstance(exc, AppError):
        return f"{exc.message} {exc.details}" if exc.details else exc.message
    return str(exc) or exc.__class__.__name__
