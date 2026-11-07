"""Infrastructure assessment service.

Targets are either an IaC repository (already in the asset inventory) or a
container image (allowlisted registry). Findings go through the same ingestion
pipeline as repository scans, so deduplication, risk and remediation are shared.

Execution is separated from the API: the API creates a PENDING row and enqueues
``INFRA_SCAN``; the worker runs the scanner and writes the outcome.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    InfraScanner,
    InfraScanStatus,
    InfraTargetKind,
    JobKind,
    Severity,
)
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.modules.assets.models import Asset
from app.modules.assets.service import resolve_access_token
from app.modules.findings import service as findings_service
from app.modules.findings.models import Finding
from app.modules.infrastructure import scanners
from app.modules.infrastructure.models import InfrastructureScan
from app.workers import queue
from app.workers.checkout import cleanup_workspace, clone_repository, workspace_for

logger = get_logger(__name__)

_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,300}$")
_DEFAULT_REGISTRIES = {"docker.io", "registry-1.docker.io"}


def _now() -> datetime:
    return datetime.now(UTC)


def _registry(reference: str) -> str:
    """Docker reference grammar: a first segment with a dot/colon is a registry."""
    first = reference.split("/", 1)[0]
    if "/" in reference and ("." in first or ":" in first or first == "localhost"):
        return first.lower()
    return "docker.io"


def _validate_image_ref(reference: str) -> str:
    reference = reference.strip()
    if not _IMAGE_REF.match(reference) or reference.startswith("-"):
        raise ValidationError("Invalid container image reference")
    settings = get_settings()
    registry = _registry(reference)
    allowed = {item.lower() for item in settings.allowed_image_registries} or _DEFAULT_REGISTRIES
    if registry not in allowed and not any(registry.endswith(f".{entry}") for entry in allowed):
        raise ValidationError(
            "Container registry is not allowlisted",
            details={"registry": registry, "allowed": sorted(allowed)},
        )
    return reference


def _adapter_for(target_kind: str, scanner: str) -> scanners.InfraAdapter:
    try:
        adapter = scanners.get_adapter(scanner)
    except KeyError as exc:
        raise ValidationError("Unknown infrastructure scanner") from exc
    if adapter.target_kind != target_kind:
        raise ValidationError(
            "Scanner does not support this target kind",
            details={"scanner": scanner, "target_kind": target_kind},
        )
    return adapter


def _image_asset(db: Session, reference: str) -> Asset:
    external_ref = f"docker://{reference}"
    asset = db.execute(
        select(Asset).where(Asset.kind == "CONTAINER_IMAGE", Asset.external_ref == external_ref)
    ).scalar_one_or_none()
    if asset is not None:
        return asset
    asset = Asset(
        name=reference[:200],
        kind="CONTAINER_IMAGE",
        repo_url=None,
        external_ref=external_ref,
        provider="NONE",
        default_branch="main",
        description="Container image registered for infrastructure assessment",
    )
    db.add(asset)
    db.flush()
    return asset


def create_scan(
    db: Session,
    *,
    target_kind: str,
    scanner: str,
    asset_id: uuid.UUID | None = None,
    target_ref: str | None = None,
    requested_by: str = "system",
    trigger: str = "MANUAL",
) -> InfrastructureScan:
    settings = get_settings()
    if not settings.infrastructure_enabled:
        raise ValidationError("Infrastructure assessment is disabled")
    if target_kind not in {item.value for item in InfraTargetKind}:
        raise ValidationError("Unknown target kind")
    if scanner not in {item.value for item in InfraScanner}:
        raise ValidationError("Unknown infrastructure scanner")
    _adapter_for(target_kind, scanner)

    asset: Asset | None = None
    if target_kind == "CONTAINER_IMAGE":
        if not target_ref:
            raise ValidationError("target_ref is required for a container image")
        reference = _validate_image_ref(target_ref)
        asset = _image_asset(db, reference)
        resolved_ref = reference
    else:
        if asset_id is None:
            raise ValidationError("asset_id is required for an IaC target")
        asset = db.get(Asset, asset_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        if asset.kind != "REPOSITORY" or not asset.repo_url:
            raise ValidationError("IaC targets must be repository assets")
        resolved_ref = asset.repo_url

    active = db.execute(
        select(InfrastructureScan).where(
            InfrastructureScan.target_kind == target_kind,
            InfrastructureScan.target_ref == resolved_ref,
            InfrastructureScan.scanner == scanner,
            InfrastructureScan.status.in_(
                [InfraScanStatus.PENDING.value, InfraScanStatus.RUNNING.value]
            ),
        )
    ).scalar_one_or_none()
    if active is not None:
        raise ConflictError(
            "An assessment of this target is already active",
            details={"scan_id": str(active.id)},
        )

    row = InfrastructureScan(
        asset_id=asset.id if asset else None,
        target_kind=target_kind,
        target_ref=resolved_ref,
        scanner=scanner,
        status=InfraScanStatus.PENDING.value,
        triggered_by=trigger,
        requested_by=requested_by[:120],
    )
    db.add(row)
    db.flush()
    queue.enqueue_once(
        db,
        JobKind.INFRA_SCAN,
        {"scan_id": str(row.id)},
        match={"scan_id": str(row.id)},
    )
    logger.info(
        "infrastructure scan requested",
        extra={"extra_fields": {"scan_id": str(row.id), "scanner": scanner, "target": resolved_ref}},
    )
    return row


def list_scans(
    db: Session,
    params: PageParams,
    *,
    asset_id: uuid.UUID | None = None,
    statuses: list[str] | None = None,
    scanner: str | None = None,
    target_kind: str | None = None,
) -> tuple[list[InfrastructureScan], int]:
    stmt = select(InfrastructureScan)
    if asset_id:
        stmt = stmt.where(InfrastructureScan.asset_id == asset_id)
    if statuses:
        stmt = stmt.where(InfrastructureScan.status.in_(statuses))
    if scanner:
        stmt = stmt.where(InfrastructureScan.scanner == scanner)
    if target_kind:
        stmt = stmt.where(InfrastructureScan.target_kind == target_kind)
    stmt = stmt.order_by(InfrastructureScan.created_at.desc())
    return paginate(db, stmt, params)


def get_scan_or_404(db: Session, scan_id: uuid.UUID) -> InfrastructureScan:
    row = db.get(InfrastructureScan, scan_id)
    if row is None:
        raise NotFoundError("Infrastructure scan not found")
    return row


def _fail(db: Session, row: InfrastructureScan, message: str) -> None:
    row.status = InfraScanStatus.FAILED.value
    row.error_message = message[:4000]
    row.finished_at = _now()
    if row.started_at:
        row.duration_seconds = int((row.finished_at - row.started_at).total_seconds())
    if row.asset_id:
        asset = db.get(Asset, row.asset_id)
        if asset is not None:
            asset.last_infra_scan_status = InfraScanStatus.FAILED.value
            asset.last_infra_scan_at = row.finished_at


def execute_scan(db: Session, scan_id: uuid.UUID, heartbeat: Any | None = None) -> None:
    row = db.get(InfrastructureScan, scan_id)
    if row is None:
        logger.warning("infrastructure scan not found", extra={"extra_fields": {"scan_id": str(scan_id)}})
        return
    if row.status not in {InfraScanStatus.PENDING.value, InfraScanStatus.RUNNING.value}:
        logger.info(
            "infrastructure scan skipped (not pending)",
            extra={"extra_fields": {"scan_id": str(scan_id), "status": row.status}},
        )
        return

    row.status = InfraScanStatus.RUNNING.value
    row.started_at = row.started_at or _now()
    row.error_message = None
    if row.asset_id:
        asset = db.get(Asset, row.asset_id)
        if asset is not None:
            asset.last_infra_scan_status = InfraScanStatus.RUNNING.value
    db.commit()

    workspace: Path | None = None
    try:
        adapter = _adapter_for(row.target_kind, row.scanner)
        available = adapter.check_availability()
        if not available.available:
            raise ValidationError(available.error or f"{adapter.name} is unavailable")

        target_path = row.target_ref
        workspace = workspace_for("infra", row.id)
        if row.target_kind != "CONTAINER_IMAGE":
            asset = db.get(Asset, row.asset_id) if row.asset_id else None
            if asset is None or not asset.repo_url:
                raise ValidationError("Repository asset no longer exists")
            checkout = clone_repository(
                repo_url=asset.repo_url,
                branch=asset.default_branch,
                token=resolve_access_token(db, asset),
                destination=workspace / "repo",
            )
            row.commit_sha = checkout.commit_sha
            target_path = str(checkout.path)

        report_dir = workspace / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.json"

        if heartbeat is not None:
            heartbeat()
        result = adapter.run(target_path, report_path, cwd=report_dir)
        if result.timed_out:
            raise ValidationError(f"{adapter.name} timed out after {result.duration_seconds}s")
        if not adapter.accepts_exit_code(result.exit_code):
            raise ValidationError(
                f"{adapter.name} exited with code {result.exit_code}",
                details={"stderr": result.stderr_excerpt[:1000]},
            )

        payload = adapter.read(report_path)
        normalized = adapter.parse_result(payload, target=row.target_ref)
        settings = get_settings()
        truncated = len(normalized) > settings.infrastructure_max_findings
        normalized = normalized[: settings.infrastructure_max_findings]

        counts = dict.fromkeys(Severity, 0)
        for finding in normalized:
            counts[Severity(finding.severity)] += 1
        if normalized and row.asset_id:
            findings_service.record_findings(
                db,
                asset_id=row.asset_id,
                scan_id=None,
                normalized=normalized,
                discovery_source="INFRASTRUCTURE_SCAN",
                actor="scanner",
            )

        row.status = InfraScanStatus.COMPLETED.value
        row.total_findings = len(normalized)
        row.critical_count = counts[Severity.CRITICAL]
        row.high_count = counts[Severity.HIGH]
        row.medium_count = counts[Severity.MEDIUM]
        row.low_count = counts[Severity.LOW]
        row.scanner_version = available.version
        row.metadata_json = {
            "command": result.command,
            "exit_code": result.exit_code,
            "duration_seconds": result.duration_seconds,
            "findings_truncated": truncated,
            "stderr_excerpt": result.stderr_excerpt[:1000] if result.stderr else "",
        }
        row.finished_at = _now()
        if row.started_at:
            row.duration_seconds = int((row.finished_at - row.started_at).total_seconds())
        if row.asset_id:
            asset = db.get(Asset, row.asset_id)
            if asset is not None:
                asset.last_infra_scan_at = row.finished_at
                asset.last_infra_scan_status = InfraScanStatus.COMPLETED.value
        db.commit()
        logger.info(
            "infrastructure scan completed",
            extra={
                "extra_fields": {
                    "scan_id": str(row.id),
                    "scanner": row.scanner,
                    "findings": row.total_findings,
                }
            },
        )
    except Exception as exc:
        db.rollback()
        logger.exception(
            "infrastructure scan failed", extra={"extra_fields": {"scan_id": str(scan_id)}}
        )
        current = db.get(InfrastructureScan, scan_id)
        if current is not None:
            _fail(db, current, str(exc)[:4000])
            db.commit()
    finally:
        cleanup_workspace(workspace)


def summary(db: Session) -> dict[str, Any]:
    by_kind = {
        kind: int(count)
        for kind, count in db.execute(
            select(InfrastructureScan.target_kind, func.count(InfrastructureScan.id)).group_by(
                InfrastructureScan.target_kind
            )
        ).all()
    }
    active = int(
        db.execute(
            select(func.count(InfrastructureScan.id)).where(
                InfrastructureScan.status.in_(
                    [InfraScanStatus.PENDING.value, InfraScanStatus.RUNNING.value]
                )
            )
        ).scalar_one()
    )
    scans_with_findings = {
        "CRITICAL": int(
            db.execute(
                select(func.count(InfrastructureScan.id)).where(InfrastructureScan.critical_count > 0)
            ).scalar_one()
        ),
        "HIGH": int(
            db.execute(
                select(func.count(InfrastructureScan.id)).where(InfrastructureScan.high_count > 0)
            ).scalar_one()
        ),
    }
    findings = {
        severity: int(
            db.execute(
                select(func.count(Finding.id)).where(
                    Finding.scanner.in_([scanner.value for scanner in InfraScanner]),
                    Finding.status.in_(ACTIVE_FINDING_STATUSES),
                    Finding.severity == severity,
                )
            ).scalar_one()
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }
    last = db.execute(select(func.max(InfrastructureScan.finished_at))).scalar_one()
    return {
        "enabled": get_settings().infrastructure_enabled,
        "active": active,
        "by_target_kind": by_kind,
        "scans_with_findings": scans_with_findings,
        "open_findings_by_severity": findings,
        "last_scan_at": last.isoformat() if last else None,
        "scanners": scanner_status(db),
    }


def scanner_status(db: Session) -> list[dict[str, Any]]:
    """Availability from two sources: the local binary and recent evidence.

    The API container does not ship the scanner binaries (only the worker does),
    so a local probe alone would report every scanner as missing. A scanner that
    has completed an assessment is available regardless of where the probe ran.
    """
    rows = scanners.availability()
    for row in rows:
        last = db.execute(
            select(func.max(InfrastructureScan.finished_at)).where(
                InfrastructureScan.scanner == row["scanner"],
                InfrastructureScan.status == InfraScanStatus.COMPLETED.value,
            )
        ).scalar_one()
        row["last_success_at"] = last.isoformat() if last else None
        row["available_evidence"] = last is not None
        row["available"] = bool(row["available"] or last is not None)
        if row["available"] and row["error"]:
            row["error"] = None
    return rows
