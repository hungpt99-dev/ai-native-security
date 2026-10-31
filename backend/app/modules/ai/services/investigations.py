"""Investigation service: runs the workflow, persists the report and its evidence."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import InvestigationStatus
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.modules.ai.agents.security_analyst import INVESTIGATION_PROMPT
from app.modules.ai.models import InvestigationEvidence, SecurityInvestigation
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.providers.registry import get_provider
from app.modules.ai.workflows.investigation import (
    WORKFLOW_NAME,
    WORKFLOW_VERSION,
    build_graph,
)
from app.modules.findings.models import Finding
from app.modules.risk_analysis import service as risk_service
from app.modules.security_intelligence.context_builder import SecurityContextBuilder
from app.modules.security_intelligence.schemas import SecurityContext
from app.modules.security_policies import service as policies_service

logger = get_logger(__name__)


def investigate(
    db: Session,
    finding_id: uuid.UUID,
    *,
    provider: AIProvider | None = None,
    principal: str = "system",
) -> SecurityInvestigation:
    settings = get_settings()
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError("Finding not found", details={"finding_id": str(finding_id)})

    policy, _key, _version = policies_service.risk_policy(db)
    provider = provider or get_provider()
    started = datetime.now(UTC)

    if not settings.ai_enabled or not provider.is_configured():
        return _persist_without_ai(db, finding, started, provider)

    graph = build_graph(db, provider, principal=principal, policy=policy)
    state = graph.invoke(
        {
            "finding_id": str(finding.id),
            "attempts": 0,
            "trace": [],
        }
    )
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)

    context: SecurityContext | None = (
        SecurityContext.model_validate(state["context"]) if state.get("context") else None
    )
    output = state.get("output")
    error = state.get("error")

    status = InvestigationStatus.INCONCLUSIVE.value
    missing: list[dict[str, Any]] = []
    if context is not None:
        missing.extend(item.model_dump(mode="json") for item in context.missing_information)
    if output:
        status = output.get("status") or InvestigationStatus.INCONCLUSIVE.value
        for text in dict.fromkeys(output.get("missing_information") or []):
            missing.append(
                {"code": "ai_reported", "message": text, "affects": ["investigation"]}
            )
    if error:
        missing.append(
            {
                "code": "ai_unavailable_for_investigation",
                "message": (
                    f"AI investigation failed ({error.get('code')}); no impact conclusion is available."
                ),
                "affects": ["investigation"],
            }
        )

    risk = risk_service.latest(db, finding.id)

    investigation = SecurityInvestigation(
        finding_id=finding.id,
        asset_id=finding.asset_id,
        context_snapshot_id=uuid.UUID(state["snapshot_id"]) if state.get("snapshot_id") else None,
        ai_execution_id=uuid.UUID(state["execution_id"]) if state.get("execution_id") else None,
        risk_assessment_id=risk.id if risk else None,
        status=status,
        summary=(output or {}).get("summary") or _no_ai_summary(error),
        impact_analysis=(output or {}).get("impact_analysis"),
        exploitability_analysis=(output or {}).get("exploitability_analysis"),
        confidence=(output or {}).get("confidence"),
        evidence_ids=[reference.get("key") for reference in (output or {}).get("evidence") or []],
        missing_information=missing,
        next_steps=(output or {}).get("next_steps") or [],
        answers=(output or {}).get("answers") or {},
        workflow_name=WORKFLOW_NAME,
        workflow_version=WORKFLOW_VERSION,
        model=settings.ai_model if output else "",
        prompt_id=INVESTIGATION_PROMPT.id,
        prompt_version=INVESTIGATION_PROMPT.version,
        started_at=started,
        finished_at=datetime.now(UTC),
        duration_ms=duration_ms,
        error_code=(error or {}).get("code"),
        error_message=(error or {}).get("message"),
    )
    db.add(investigation)
    db.flush()

    if context is not None:
        for item in context.evidence:
            db.add(
                InvestigationEvidence(
                    investigation_id=investigation.id,
                    evidence_key=item.key,
                    kind=item.kind,
                    source=item.source,
                    locator=item.locator,
                    excerpt=item.text[:1000],
                    sha256=item.sha256,
                    evidence_metadata={
                        "cited": item.key in (investigation.evidence_ids or []),
                        "injection_markers": item.injection_markers,
                    },
                )
            )
    db.commit()
    logger.info(
        "investigation stored",
        extra={
            "extra_fields": {
                "investigation_id": str(investigation.id),
                "finding_id": str(finding.id),
                "status": investigation.status,
                "confidence": float(investigation.confidence)
                if investigation.confidence is not None
                else None,
                "duration_ms": duration_ms,
                "workflow_trace": state.get("trace"),
            }
        },
    )
    return investigation


def _persist_without_ai(
    db: Session, finding: Finding, started: datetime, provider: AIProvider
) -> SecurityInvestigation:
    """Explicit, labelled degradation: no AI, no fabricated conclusion."""
    builder = SecurityContextBuilder()
    context = builder.build(db, finding.id)
    snapshot = builder.persist(db, context, finding=finding)
    missing = [item.model_dump(mode="json") for item in context.missing_information]
    missing.append(
        {
            "code": "ai_unavailable_for_investigation",
            "message": "AI is disabled or not configured, so no investigation was performed.",
            "affects": ["investigation"],
        }
    )
    investigation = SecurityInvestigation(
        finding_id=finding.id,
        asset_id=finding.asset_id,
        context_snapshot_id=snapshot.id,
        status=InvestigationStatus.INCONCLUSIVE.value,
        summary="No AI investigation was performed (AI disabled or not configured).",
        confidence=None,
        missing_information=missing,
        next_steps=["Configure an AI provider, then re-run the investigation."],
        workflow_name=WORKFLOW_NAME,
        workflow_version=WORKFLOW_VERSION,
        model="",
        prompt_id=INVESTIGATION_PROMPT.id,
        prompt_version=INVESTIGATION_PROMPT.version,
        started_at=started,
        finished_at=datetime.now(UTC),
        duration_ms=0,
        error_code="ai_unavailable",
        error_message=f"provider={provider.name} enabled={get_settings().ai_enabled}",
    )
    db.add(investigation)
    db.flush()
    for item in context.evidence:
        db.add(
            InvestigationEvidence(
                investigation_id=investigation.id,
                evidence_key=item.key,
                kind=item.kind,
                source=item.source,
                locator=item.locator,
                excerpt=item.text[:1000],
                sha256=item.sha256,
                evidence_metadata={"cited": False},
            )
        )
    db.commit()
    return investigation


def _no_ai_summary(error: dict[str, Any] | None) -> str:
    if error:
        return f"AI investigation could not be completed ({error.get('code')})."
    return "No conclusion could be drawn from the available evidence."


def latest(db: Session, finding_id: uuid.UUID) -> SecurityInvestigation | None:
    return db.execute(
        select(SecurityInvestigation)
        .where(SecurityInvestigation.finding_id == finding_id)
        .order_by(SecurityInvestigation.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def history(db: Session, finding_id: uuid.UUID, limit: int = 10) -> list[SecurityInvestigation]:
    return list(
        db.execute(
            select(SecurityInvestigation)
            .where(SecurityInvestigation.finding_id == finding_id)
            .order_by(SecurityInvestigation.created_at.desc())
            .limit(limit)
        ).scalars()
    )


def evidence_for(db: Session, investigation_id: uuid.UUID) -> list[InvestigationEvidence]:
    return list(
        db.execute(
            select(InvestigationEvidence)
            .where(InvestigationEvidence.investigation_id == investigation_id)
            .order_by(InvestigationEvidence.evidence_key)
        ).scalars()
    )


def to_dict(
    investigation: SecurityInvestigation, *, evidence: list[InvestigationEvidence] | None = None
) -> dict[str, Any]:
    return {
        "id": str(investigation.id),
        "finding_id": str(investigation.finding_id),
        "asset_id": str(investigation.asset_id),
        "status": investigation.status,
        "summary": investigation.summary,
        "impact_analysis": investigation.impact_analysis,
        "exploitability_analysis": investigation.exploitability_analysis,
        "confidence": float(investigation.confidence) if investigation.confidence is not None else None,
        "answers": investigation.answers,
        "evidence_ids": investigation.evidence_ids,
        "missing_information": investigation.missing_information,
        "next_steps": investigation.next_steps,
        "workflow": {
            "name": investigation.workflow_name,
            "version": investigation.workflow_version,
        },
        "model": investigation.model,
        "prompt_id": investigation.prompt_id,
        "prompt_version": investigation.prompt_version,
        "error_code": investigation.error_code,
        "error_message": investigation.error_message,
        "duration_ms": investigation.duration_ms,
        "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
        "evidence": [
            {
                "key": item.evidence_key,
                "kind": item.kind,
                "source": item.source,
                "locator": item.locator,
                "excerpt": item.excerpt,
                "sha256": item.sha256,
                "cited": item.evidence_metadata.get("cited", False),
            }
            for item in (evidence or [])
        ],
    }
