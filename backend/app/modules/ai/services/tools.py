"""Read-only tool registry for the security assistant.

The model never executes anything. It *asks* for a tool call; the platform
validates the arguments against a Pydantic model, executes a fixed function and
returns rows. There is no SQL passthrough, no shell, no URL fetch and no
filesystem access anywhere in this module.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.enums import ACTIVE_FINDING_STATUSES, RemediationStatus, Severity
from app.core.errors import ValidationError as AppValidationError
from app.modules.assets.models import Asset
from app.modules.findings.models import Finding
from app.modules.knowledge_base import service as knowledge_service
from app.modules.remediation.models import RemediationRecommendation
from app.modules.risk_analysis.models import RiskAssessment
from app.modules.scans.models import Scan

MAX_LIMIT = 50


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmptyArguments(ToolArguments):
    pass


class LimitArguments(ToolArguments):
    limit: int = Field(default=10, ge=1, le=MAX_LIMIT)


class FindingFilterArguments(ToolArguments):
    severity: list[str] | None = None
    status: list[str] | None = None
    asset_id: uuid.UUID | None = None
    cve_id: str | None = Field(default=None, max_length=32)
    query: str | None = Field(default=None, max_length=200)
    sort: str = Field(default="risk", pattern="^(risk|cvss|recent)$")
    limit: int = Field(default=20, ge=1, le=MAX_LIMIT)


class FindingIdArguments(ToolArguments):
    finding_id: uuid.UUID


class AssetIdArguments(ToolArguments):
    asset_id: uuid.UUID


class AssetArgumentsWithLimit(ToolArguments):
    asset_id: uuid.UUID | None = None
    limit: int = Field(default=10, ge=1, le=MAX_LIMIT)


class RemediationFilterArguments(ToolArguments):
    status: str | None = None
    asset_id: uuid.UUID | None = None
    limit: int = Field(default=20, ge=1, le=MAX_LIMIT)


class SearchArguments(ToolArguments):
    query: str = Field(min_length=2, max_length=200)
    limit: int = Field(default=10, ge=1, le=MAX_LIMIT)


@dataclass
class ToolSpec:
    name: str
    description: str
    arguments: type[ToolArguments]
    run: Any

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.arguments.model_json_schema(),
        }


@dataclass
class ToolResult:
    name: str
    arguments: dict[str, Any]
    rows: Any = None
    count: int = 0
    error: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.name,
            "arguments": self.arguments,
            "count": self.count,
            "rows": self.rows,
            "error": self.error,
            "meta": self.meta,
        }


def _scope_ids(db: Session, scope: frozenset[uuid.UUID] | None) -> list[uuid.UUID] | None:
    if scope is None:
        return None
    return list(scope)


def _ensure_scope(asset_id: uuid.UUID | None, scope: frozenset[uuid.UUID] | None) -> None:
    if scope is not None and asset_id is not None and asset_id not in scope:
        raise AppValidationError("Asset is outside the caller's scope", details={"asset_id": str(asset_id)})


def _latest_risk(db: Session, finding_ids: list[uuid.UUID]) -> dict[uuid.UUID, RiskAssessment]:
    if not finding_ids:
        return {}
    rows = (
        db.execute(
            select(RiskAssessment)
            .where(RiskAssessment.finding_id.in_(finding_ids))
            .order_by(RiskAssessment.finding_id, RiskAssessment.created_at.desc())
        )
        .scalars()
        .all()
    )
    latest: dict[uuid.UUID, RiskAssessment] = {}
    for row in rows:
        latest.setdefault(row.finding_id, row)
    return latest


def tool_platform_overview(
    db: Session, args: ToolArguments, scope: frozenset[uuid.UUID] | None
) -> ToolResult:
    asset_ids = _scope_ids(db, scope)
    asset_stmt = select(func.count(Asset.id))
    finding_stmt = select(func.count(Finding.id)).where(Finding.status.in_(ACTIVE_FINDING_STATUSES))
    if asset_ids is not None:
        asset_stmt = asset_stmt.where(Asset.id.in_(asset_ids))
        finding_stmt = finding_stmt.where(Finding.asset_id.in_(asset_ids))
    kev_stmt = select(func.count(Finding.id)).where(
        Finding.metadata_json["intel"]["is_kev"].astext == "true",
        Finding.status.in_(ACTIVE_FINDING_STATUSES),
    )
    if asset_ids is not None:
        kev_stmt = kev_stmt.where(Finding.asset_id.in_(asset_ids))
    pending_remediation = db.execute(
        select(func.count(RemediationRecommendation.id)).where(
            RemediationRecommendation.status.in_(
                [
                    RemediationStatus.AWAITING_APPROVAL.value,
                    RemediationStatus.APPROVED.value,
                    RemediationStatus.VALIDATING.value,
                ]
            )
        )
    ).scalar_one()
    rows = {
        "assets": int(db.execute(asset_stmt).scalar_one()),
        "active_findings": int(db.execute(finding_stmt).scalar_one()),
        "kev_findings": int(db.execute(kev_stmt).scalar_one()),
        "open_remediation_proposals": int(pending_remediation),
        "critical_open": int(
            db.execute(
                select(func.count(Finding.id)).where(
                    Finding.severity == Severity.CRITICAL.value,
                    Finding.status.in_(ACTIVE_FINDING_STATUSES),
                    *([Finding.asset_id.in_(asset_ids)] if asset_ids is not None else []),
                )
            ).scalar_one()
        ),
    }
    return ToolResult("platform_overview", {}, rows, count=1)


def tool_list_findings(
    db: Session, args: FindingFilterArguments, scope: frozenset[uuid.UUID] | None
) -> ToolResult:
    if args.asset_id is not None:
        _ensure_scope(args.asset_id, scope)
    stmt = select(Finding).where(Finding.status.in_(ACTIVE_FINDING_STATUSES))
    if args.severity:
        stmt = stmt.where(Finding.severity.in_([value.upper() for value in args.severity]))
    if args.status:
        stmt = stmt.where(Finding.status.in_([value.upper() for value in args.status]))
    if args.asset_id:
        stmt = stmt.where(Finding.asset_id == args.asset_id)
    if args.cve_id:
        stmt = stmt.where(Finding.cve_id == args.cve_id.upper())
    if args.query:
        pattern = f"%{args.query.strip()}%"
        stmt = stmt.where(Finding.title.ilike(pattern) | Finding.package_name.ilike(pattern))
    scope_ids = _scope_ids(db, scope)
    if scope_ids is not None:
        stmt = stmt.where(Finding.asset_id.in_(scope_ids))
    if args.sort == "cvss":
        stmt = stmt.order_by(Finding.cvss_score.desc().nullslast())
    elif args.sort == "recent":
        stmt = stmt.order_by(Finding.last_detected_at.desc())
    else:
        stmt = stmt.order_by(Finding.severity.asc(), Finding.cvss_score.desc().nullslast())
    rows = db.execute(stmt.limit(args.limit)).scalars().all()
    risks = _latest_risk(db, [row.id for row in rows])
    payload = []
    for row in rows:
        risk = risks.get(row.id)
        payload.append(
            {
                "finding_id": str(row.id),
                "asset_id": str(row.asset_id),
                "scanner": row.scanner,
                "severity": row.severity,
                "title": row.title[:160],
                "package": row.package_name,
                "version": row.package_version,
                "cve_id": row.cve_id,
                "status": row.status,
                "risk_level": risk.risk_level if risk else None,
                "final_score": risk.final_score if risk else None,
                "is_kev": bool((row.metadata_json or {}).get("intel", {}).get("is_kev")),
            }
        )
    return ToolResult("list_findings", args.model_dump(mode="json"), payload, count=len(payload))


def tool_finding_details(
    db: Session, args: FindingIdArguments, scope: frozenset[uuid.UUID] | None
) -> ToolResult:
    finding = db.get(Finding, args.finding_id)
    if finding is None:
        return ToolResult("finding_details", args.model_dump(mode="json"), None, error="not_found")
    _ensure_scope(finding.asset_id, scope)
    risk = db.execute(
        select(RiskAssessment)
        .where(RiskAssessment.finding_id == finding.id)
        .order_by(RiskAssessment.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    recommendation = db.execute(
        select(RemediationRecommendation)
        .where(RemediationRecommendation.finding_id == finding.id)
        .order_by(RemediationRecommendation.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    asset = db.get(Asset, finding.asset_id)
    row = {
        "finding_id": str(finding.id),
        "title": finding.title,
        "description": (finding.description or "")[:800],
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "status": finding.status,
        "asset": {
            "id": str(finding.asset_id),
            "name": asset.name if asset else None,
            "repo_url": asset.repo_url if asset else None,
        },
        "package": finding.package_name,
        "version": finding.package_version,
        "cve_id": finding.cve_id,
        "cvss": float(finding.cvss_score) if finding.cvss_score is not None else None,
        "risk": {
            "level": risk.risk_level,
            "final_score": risk.final_score,
            "confidence": float(risk.confidence) if risk and risk.confidence is not None else None,
            "summary": risk.summary,
            "deterministic_only": risk.deterministic_only,
        }
        if risk
        else None,
        "remediation": {
            "strategy": recommendation.strategy,
            "status": recommendation.status,
            "recommended_version": recommendation.recommended_version,
        }
        if recommendation
        else None,
    }
    return ToolResult("finding_details", args.model_dump(mode="json"), row, count=1)


def tool_top_risk_assets(db: Session, args: LimitArguments, scope: frozenset[uuid.UUID] | None) -> ToolResult:
    rows = db.execute(
        select(
            Asset.id,
            Asset.name,
            Asset.repo_url,
            func.max(RiskAssessment.final_score).label("max_score"),
            func.count(RiskAssessment.id).label("assessments"),
        )
        .join(RiskAssessment, RiskAssessment.asset_id == Asset.id)
        .group_by(Asset.id, Asset.name, Asset.repo_url)
        .order_by(func.max(RiskAssessment.final_score).desc())
        .limit(args.limit)
    ).all()
    scope_ids = _scope_ids(db, scope)
    payload = [
        {
            "asset_id": str(asset_id),
            "name": name,
            "repo_url": repo_url,
            "highest_final_score": int(max_score or 0),
            "assessments": int(assessments),
        }
        for asset_id, name, repo_url, max_score, assessments in rows
        if scope_ids is None or asset_id in scope_ids
    ]
    return ToolResult("top_risk_assets", args.model_dump(mode="json"), payload, count=len(payload))


def tool_asset_overview(
    db: Session, args: AssetIdArguments, scope: frozenset[uuid.UUID] | None
) -> ToolResult:
    _ensure_scope(args.asset_id, scope)
    asset = db.get(Asset, args.asset_id)
    if asset is None:
        return ToolResult("asset_overview", args.model_dump(mode="json"), None, error="not_found")
    counts = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.asset_id == asset.id, Finding.status.in_(ACTIVE_FINDING_STATUSES))
        .group_by(Finding.severity)
    ).all()
    latest_scan = db.execute(
        select(Scan).where(Scan.asset_id == asset.id).order_by(Scan.created_at.desc()).limit(1)
    ).scalar_one_or_none()
    risk = db.execute(
        select(RiskAssessment)
        .where(RiskAssessment.asset_id == asset.id)
        .order_by(RiskAssessment.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    row = {
        "asset_id": str(asset.id),
        "name": asset.name,
        "repo_url": asset.repo_url,
        "provider": asset.provider,
        "default_branch": asset.default_branch,
        "monitoring_enabled": asset.monitoring_enabled,
        "active_findings_by_severity": {severity: int(count) for severity, count in counts},
        "latest_scan": {
            "id": str(latest_scan.id),
            "status": latest_scan.status,
            "created_at": latest_scan.created_at.isoformat() if latest_scan else None,
            "total_findings": latest_scan.total_findings,
        }
        if latest_scan
        else None,
        "highest_risk": {
            "level": risk.risk_level,
            "final_score": risk.final_score,
        }
        if risk
        else None,
    }
    return ToolResult("asset_overview", args.model_dump(mode="json"), row, count=1)


def tool_kev_findings(db: Session, args: LimitArguments, scope: frozenset[uuid.UUID] | None) -> ToolResult:
    stmt = (
        select(Finding)
        .where(
            Finding.metadata_json["intel"]["is_kev"].astext == "true",
            Finding.status.in_(ACTIVE_FINDING_STATUSES),
        )
        .order_by(Finding.cvss_score.desc().nullslast())
        .limit(args.limit)
    )
    scope_ids = _scope_ids(db, scope)
    if scope_ids is not None:
        stmt = stmt.where(Finding.asset_id.in_(scope_ids))
    rows = db.execute(stmt).scalars().all()
    payload = [
        {
            "finding_id": str(row.id),
            "asset_id": str(row.asset_id),
            "title": row.title[:160],
            "cve_id": row.cve_id,
            "severity": row.severity,
            "package": row.package_name,
        }
        for row in rows
    ]
    return ToolResult("kev_findings", args.model_dump(mode="json"), payload, count=len(payload))


def tool_remediation_queue(
    db: Session, args: RemediationFilterArguments, scope: frozenset[uuid.UUID] | None
) -> ToolResult:
    if args.asset_id is not None:
        _ensure_scope(args.asset_id, scope)
    stmt = select(RemediationRecommendation)
    if args.status:
        stmt = stmt.where(RemediationRecommendation.status == args.status.upper())
    if args.asset_id:
        stmt = stmt.where(RemediationRecommendation.asset_id == args.asset_id)
    scope_ids = _scope_ids(db, scope)
    if scope_ids is not None:
        stmt = stmt.where(RemediationRecommendation.asset_id.in_(scope_ids))
    rows = (
        db.execute(stmt.order_by(RemediationRecommendation.created_at.desc()).limit(args.limit))
        .scalars()
        .all()
    )
    payload = [
        {
            "recommendation_id": str(row.id),
            "finding_id": str(row.finding_id),
            "asset_id": str(row.asset_id),
            "strategy": row.strategy,
            "status": row.status,
            "package": row.target_package,
            "from_version": row.current_version,
            "to_version": row.recommended_version,
            "version_verified": row.version_verified,
            "summary": (row.summary or "")[:200],
        }
        for row in rows
    ]
    return ToolResult("remediation_queue", args.model_dump(mode="json"), payload, count=len(payload))


def tool_recent_scans(
    db: Session, args: AssetArgumentsWithLimit, scope: frozenset[uuid.UUID] | None
) -> ToolResult:
    if args.asset_id is not None:
        _ensure_scope(args.asset_id, scope)
    stmt = select(Scan, Asset.name).join(Asset, Asset.id == Scan.asset_id)
    if args.asset_id:
        stmt = stmt.where(Scan.asset_id == args.asset_id)
    scope_ids = _scope_ids(db, scope)
    if scope_ids is not None:
        stmt = stmt.where(Scan.asset_id.in_(scope_ids))
    rows = db.execute(stmt.order_by(Scan.created_at.desc()).limit(args.limit)).all()
    payload = [
        {
            "scan_id": str(scan.id),
            "asset_id": str(scan.asset_id),
            "asset_name": name,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "total_findings": scan.total_findings,
            "new_findings": scan.new_findings,
            "resolved_findings": scan.resolved_findings,
            "duration_seconds": scan.duration_seconds,
        }
        for scan, name in rows
    ]
    return ToolResult("recent_scans", args.model_dump(mode="json"), payload, count=len(payload))


def tool_decision_history(
    db: Session, args: FindingIdArguments, scope: frozenset[uuid.UUID] | None
) -> ToolResult:
    finding = db.get(Finding, args.finding_id)
    if finding is None:
        return ToolResult("decision_history", args.model_dump(mode="json"), None, error="not_found")
    _ensure_scope(finding.asset_id, scope)
    decisions = knowledge_service.decisions_for_finding(db, finding.id)
    payload = [
        {
            "decision_id": str(row.id),
            "type": row.decision_type,
            "actor": row.actor,
            "reason": (row.reason or "")[:300],
            "at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in decisions
    ]
    return ToolResult("decision_history", args.model_dump(mode="json"), payload, count=len(payload))


def tool_search_knowledge(
    db: Session, args: SearchArguments, scope: frozenset[uuid.UUID] | None
) -> ToolResult:
    payload = knowledge_service.search(db, args.query, limit=args.limit)
    return ToolResult(
        "search_knowledge", args.model_dump(mode="json"), payload, count=len(payload.get("decisions") or [])
    )


TOOLS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            "platform_overview",
            "Counts of assets, active findings, KEV findings and open remediation proposals.",
            EmptyArguments,
            tool_platform_overview,
        ),
        ToolSpec(
            "list_findings",
            "List active findings, optionally filtered by severity, status, asset, CVE or text.",
            FindingFilterArguments,
            tool_list_findings,
        ),
        ToolSpec(
            "finding_details",
            "Full detail for one finding: risk, remediation and asset.",
            FindingIdArguments,
            tool_finding_details,
        ),
        ToolSpec(
            "top_risk_assets",
            "Assets ordered by their highest assessed risk score.",
            LimitArguments,
            tool_top_risk_assets,
        ),
        ToolSpec(
            "asset_overview",
            "One asset: severity counts, latest scan and highest risk.",
            AssetIdArguments,
            tool_asset_overview,
        ),
        ToolSpec("kev_findings", "Active findings listed in CISA KEV.", LimitArguments, tool_kev_findings),
        ToolSpec(
            "remediation_queue",
            "Remediation proposals with their lifecycle status.",
            RemediationFilterArguments,
            tool_remediation_queue,
        ),
        ToolSpec(
            "recent_scans",
            "Most recent scans, optionally for one asset.",
            AssetArgumentsWithLimit,
            tool_recent_scans,
        ),
        ToolSpec(
            "decision_history",
            "Human decisions recorded for one finding.",
            FindingIdArguments,
            tool_decision_history,
        ),
        ToolSpec(
            "search_knowledge",
            "Free-text search over recorded decisions and remediation proposals.",
            SearchArguments,
            tool_search_knowledge,
        ),
    )
}


def tool_catalog() -> list[dict[str, Any]]:
    return [spec.as_dict() for spec in TOOLS.values()]


def execute(
    db: Session,
    name: str,
    arguments: dict[str, Any],
    *,
    asset_scope: frozenset[uuid.UUID] | None = None,
) -> ToolResult:
    spec = TOOLS.get(name)
    if spec is None:
        return ToolResult(name, arguments or {}, None, error="unknown_tool")
    try:
        parsed = spec.arguments.model_validate(arguments or {})
    except ValidationError as exc:
        return ToolResult(
            name,
            arguments or {},
            None,
            error="invalid_arguments",
            meta={"errors": [error["msg"] for error in exc.errors()[:5]]},
        )
    try:
        return spec.run(db, parsed, asset_scope)
    except AppValidationError as exc:
        return ToolResult(name, parsed.model_dump(mode="json"), None, error=exc.code, meta=exc.details)


def freshness_note() -> str:
    return f"tool data retrieved at {datetime.now(UTC).replace(microsecond=0).isoformat()}"
