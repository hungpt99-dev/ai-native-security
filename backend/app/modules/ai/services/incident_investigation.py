"""Incident investigation service: build evidence, call the model, persist a report.

Persistence is append-only. A failed or unconfigured provider is recorded as an
explicitly labelled ``INCONCLUSIVE`` report — never as a plausible conclusion.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AIExecutionKind, InvestigationStatus
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.modules.ai.agents import incident_analyst
from app.modules.ai.models import AIExecution
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.providers.registry import get_provider
from app.modules.ai.schemas.outputs import IncidentInvestigationOutput
from app.modules.ai.services.executions import record_result, track_execution
from app.modules.assets.models import Asset
from app.modules.incidents import service as incidents_service
from app.modules.incidents.models import Incident, IncidentInvestigation
from app.modules.security_intelligence.models import AssetSecurityProfile

logger = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def latest(db: Session, incident_id: uuid.UUID) -> IncidentInvestigation | None:
    return db.execute(
        select(IncidentInvestigation)
        .where(IncidentInvestigation.incident_id == incident_id)
        .order_by(IncidentInvestigation.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def history(db: Session, incident_id: uuid.UUID) -> list[IncidentInvestigation]:
    return list(
        db.execute(
            select(IncidentInvestigation)
            .where(IncidentInvestigation.incident_id == incident_id)
            .order_by(IncidentInvestigation.created_at.desc())
        ).scalars()
    )


def _persist(
    db: Session,
    incident: Incident,
    *,
    status: str,
    summary: str,
    confidence: float | None,
    evidence: list[dict[str, Any]],
    missing: list[dict[str, Any]],
    actions: list[str],
    steps: list[dict[str, Any]],
    payload: dict[str, Any],
    model: str,
    execution_id: uuid.UUID | None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> IncidentInvestigation:
    row = IncidentInvestigation(
        incident_id=incident.id,
        status=status,
        summary=summary,
        confidence=confidence,
        evidence=evidence,
        missing_information=missing,
        next_actions=actions,
        attack_steps=steps,
        payload=payload,
        ai_execution_id=execution_id,
        model=model,
        prompt_id=incident_analyst.INCIDENT_PROMPT.id,
        prompt_version=incident_analyst.INCIDENT_PROMPT.version,
        error_code=error_code,
        error_message=error_message,
    )
    db.add(row)
    db.flush()
    incidents_service.add_timeline(
        db,
        incident,
        kind="AI_INVESTIGATION",
        message=f"AI investigation recorded: {status}",
        actor="ai",
        detail={
            "investigation_id": str(row.id),
            "status": status,
            "confidence": confidence,
            "execution_id": str(execution_id) if execution_id else None,
            "error_code": error_code,
        },
    )
    incident.metadata_json = {
        **(incident.metadata_json or {}),
        "last_investigation_id": str(row.id),
        "last_investigation_status": status,
    }
    db.flush()
    return row


def investigate(
    db: Session,
    incident_id: uuid.UUID,
    *,
    provider: AIProvider | None = None,
    principal: str = "system",
) -> IncidentInvestigation:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise NotFoundError("Incident not found", details={"incident_id": str(incident_id)})

    settings = get_settings()
    provider = provider or get_provider()

    if not settings.ai_enabled or not provider.is_configured():
        # The report exists to say "nobody analysed this", not to imply safety.
        return _persist(
            db,
            incident,
            status=InvestigationStatus.INCONCLUSIVE.value,
            summary=(
                "AI investigation is unavailable: no provider is configured or the AI "
                "layer is disabled. No conclusion was drawn from this incident's evidence."
            ),
            confidence=None,
            evidence=[],
            missing=[
                {
                    "code": "ai_unavailable_for_incident_investigation",
                    "message": "AI is disabled or the provider has no credentials.",
                    "affects": ["investigation"],
                }
            ],
            actions=[],
            steps=[],
            payload={"deterministic_only": True},
            model="",
            execution_id=None,
            error_code="ai_unavailable",
            error_message="AI is disabled or not configured",
        )

    data = incidents_service.details(db, incident.id)
    asset: Asset | None = data["asset"]
    profile = db.get(AssetSecurityProfile, asset.id) if asset is not None else None
    evidence = incident_analyst.build_evidence(
        incident=incident,
        asset=asset,
        profile=profile,
        events=data["events"],
        findings=data["findings"],
    )
    request = incident_analyst.build_request(evidence)
    execution: AIExecution | None = None

    try:
        with track_execution(
            db,
            kind=AIExecutionKind.INCIDENT_INVESTIGATION.value,
            request=request,
            provider_name=provider.name,
            model=settings.ai_model,
            asset_id=incident.asset_id,
            principal=principal,
            schema_id=IncidentInvestigationOutput.__name__,
        ) as tracked:
            execution = tracked
            analysis = incident_analyst.run(provider, evidence, request=request)
            record_result(tracked, analysis.result)
    except Exception as exc:  # provider, rate limit, budget, invalid output
        logger.warning(
            "incident investigation failed",
            extra={"extra_fields": {"incident_id": str(incident.id), "error": str(exc)[:300]}},
        )
        return _persist(
            db,
            incident,
            status=InvestigationStatus.INCONCLUSIVE.value,
            summary=(
                "The AI investigation failed before producing a verifiable report. "
                "The incident's deterministic evidence is unchanged."
            ),
            confidence=None,
            evidence=[],
            missing=[
                {
                    "code": "ai_investigation_failed",
                    "message": str(exc)[:500],
                    "affects": ["investigation"],
                },
                *[
                    {"code": "context_missing", "message": item, "affects": ["investigation"]}
                    for item in evidence.missing
                ],
            ],
            actions=[],
            steps=[],
            payload={"deterministic_only": True},
            model=getattr(execution, "model", "") or settings.ai_model,
            execution_id=execution.id if execution is not None else None,
            error_code="ai_investigation_failed",
            error_message=str(exc)[:2000],
        )

    output = analysis.output
    return _persist(
        db,
        incident,
        status=output.status,
        summary=output.summary,
        confidence=output.confidence,
        evidence=[ref.model_dump() for ref in output.evidence],
        missing=[
            {"code": "ai_reported", "message": message, "affects": ["investigation"]}
            for message in output.missing_information
        ],
        actions=output.containment_actions,
        steps=[step.model_dump() for step in output.attack_steps],
        payload=output.model_dump(mode="json"),
        model=execution.model if execution is not None else settings.ai_model,
        execution_id=execution.id if execution is not None else None,
    )


def to_dict(row: IncidentInvestigation) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "incident_id": str(row.incident_id),
        "status": row.status,
        "summary": row.summary,
        "confidence": row.confidence,
        "evidence": row.evidence,
        "missing_information": row.missing_information,
        "next_actions": row.next_actions,
        "attack_steps": row.attack_steps,
        "model": row.model,
        "prompt_id": row.prompt_id,
        "prompt_version": row.prompt_version,
        "ai_execution_id": str(row.ai_execution_id) if row.ai_execution_id else None,
        "error_code": row.error_code,
        "error_message": row.error_message,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
