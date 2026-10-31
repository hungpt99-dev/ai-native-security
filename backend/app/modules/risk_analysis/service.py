"""Risk assessment service: deterministic signals + optional AI judgement.

Order is fixed and enforced here:

1. build and persist the security context (deterministic),
2. compute deterministic signals (deterministic),
3. optionally ask the model for a contextual opinion (probabilistic),
4. blend through the versioned policy (deterministic),
5. persist an append-only assessment that records all five numbers separately.

If step 3 fails, the assessment is still persisted — explicitly marked
``deterministic_only`` with the failure recorded. It is never dressed up as an AI
verdict.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AIExecutionKind, Severity
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.modules.ai import agents
from app.modules.ai.errors import (
    AIBudgetExceededError,
    AIProviderError,
    AIRateLimitedError,
    AIResponseError,
    AIUnavailableError,
)
from app.modules.ai.models import AIExecution
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.providers.registry import get_provider
from app.modules.ai.services import budgets
from app.modules.ai.services.executions import record_result, track_execution
from app.modules.findings.models import Finding
from app.modules.risk_analysis import policy as policy_module
from app.modules.risk_analysis import signals as signals_module
from app.modules.risk_analysis.models import RiskAssessment
from app.modules.security_intelligence.context_builder import SecurityContextBuilder
from app.modules.security_policies import service as policies_service

logger = get_logger(__name__)

_AI_FAILURES = (
    AIUnavailableError,
    AIProviderError,
    AIRateLimitedError,
    AIResponseError,
    AIBudgetExceededError,
)

#: Severities that may be sent to a model by default. Kept as a module constant
#: *and* overridable by policy, because this is a cost/benefit decision, not a
#: technical one.
DEFAULT_AI_SEVERITIES = {Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value}


def assess(
    db: Session,
    finding_id: uuid.UUID,
    *,
    provider: AIProvider | None = None,
    principal: str = "system",
    use_ai: bool | None = None,
    scan_id: uuid.UUID | None = None,
) -> RiskAssessment:
    settings = get_settings()
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError("Finding not found", details={"finding_id": str(finding_id)})

    policy_config, policy_key, policy_version = policies_service.risk_policy(db)

    builder = SecurityContextBuilder(settings)
    context = builder.build(db, finding_id, scan_id=scan_id)
    snapshot = builder.persist(db, context, finding=finding)
    db.commit()

    signal_set = signals_module.compute_signals(context, policy_config)

    provider = provider or get_provider()
    allowed_severities = {
        str(value).upper()
        for value in (policy_config.get("gates", {}).get("allow_ai_for_severities") or DEFAULT_AI_SEVERITIES)
    }
    should_call_ai = (
        bool(settings.ai_enabled) and finding.severity.upper() in allowed_severities and (use_ai is not False)
    )
    if use_ai is True:
        should_call_ai = True

    ai_output = None
    ai_execution_id: uuid.UUID | None = None
    ai_failure: dict[str, Any] | None = None

    if not should_call_ai:
        ai_failure = {
            "code": "ai_disabled",
            "message": (
                "AI analysis was not performed: the provider is disabled/unconfigured, "
                "or the severity gate excluded this finding."
            ),
        }

    if should_call_ai:
        try:
            budgets.enforce(db)
            request = agents.risk_analyst.build_request(context)
            with track_execution(
                db,
                kind=AIExecutionKind.RISK_ASSESSMENT.value,
                request=request,
                provider_name=provider.name,
                model=settings.ai_model,
                finding_id=finding.id,
                asset_id=finding.asset_id,
                context_snapshot_id=snapshot.id,
                principal=principal,
            ) as execution:
                analysis = agents.risk_analyst.run(provider, context, request=request)
                record_result(execution, analysis.result)
                ai_execution_id = execution.id
            ai_output = analysis.output
            if analysis.dropped_evidence:
                logger.warning(
                    "model cited evidence that was not supplied",
                    extra={
                        "extra_fields": {
                            "finding_id": str(finding.id),
                            "dropped": analysis.dropped_evidence,
                        }
                    },
                )
        except _AI_FAILURES as exc:
            ai_failure = {
                "code": getattr(exc, "code", "ai_error"),
                "message": str(exc)[:500],
            }
            logger.warning(
                "risk assessment ran without AI",
                extra={
                    "extra_fields": {
                        "finding_id": str(finding.id),
                        "error_code": ai_failure["code"],
                    }
                },
            )

    blend = policy_module.combine(
        deterministic_score=signal_set.score,
        ai_score=ai_output.risk_score if ai_output else None,
        ai_level=ai_output.risk_level if ai_output else None,
        ai_confidence=ai_output.confidence if ai_output else None,
        coverage=signal_set.coverage,
        policy=policy_config,
    )

    missing_information: list[dict[str, Any]] = [
        item.model_dump(mode="json") for item in context.missing_information
    ]
    if ai_output:
        for text in dict.fromkeys(ai_output.missing_information):
            missing_information.append(
                {"code": "ai_reported", "message": text, "affects": ["risk_scoring"]}
            )
    if ai_failure:
        missing_information.append(
            {
                "code": "ai_unavailable_for_assessment",
                "message": (
                    ai_failure["message"]
                    if ai_failure["code"] == "ai_disabled"
                    else (
                        f"AI assessment failed ({ai_failure['code']}); this score is "
                        "deterministic only and must not be read as a model opinion."
                    )
                ),
                "affects": ["risk_scoring"],
            }
        )

    assessment = RiskAssessment(
        finding_id=finding.id,
        asset_id=finding.asset_id,
        context_snapshot_id=snapshot.id,
        ai_execution_id=ai_execution_id,
        policy_key=policy_key,
        policy_version=policy_version,
        cvss_score=finding.cvss_score
        if finding.cvss_score is not None
        else context.vulnerability.get("cvss_score"),
        epss_score=context.vulnerability.get("epss_score"),
        is_kev=bool(context.vulnerability.get("is_kev")),
        deterministic_score=signal_set.score,
        ai_risk_score=ai_output.risk_score if ai_output else None,
        final_score=blend["final_score"],
        risk_level=blend["risk_level"],
        ai_risk_level=ai_output.risk_level if ai_output else None,
        confidence=blend["confidence"],
        summary=ai_output.summary if ai_output else None,
        impact_analysis=ai_output.impact_analysis if ai_output else None,
        exploitability_analysis=ai_output.exploitability_analysis if ai_output else None,
        reasoning=(ai_output.summary if ai_output else None),
        signals=[signal.as_dict() for signal in signal_set.signals],
        affected_components=(ai_output.affected_components if ai_output else []),
        evidence=[
            {
                "key": item.key,
                "kind": item.kind,
                "source": item.source,
                "locator": item.locator,
                "sha256": item.sha256,
                "cited": bool(ai_output and item.key in {ref.key for ref in ai_output.evidence}),
            }
            for item in context.evidence
        ],
        missing_information=missing_information,
        recommended_actions=(ai_output.recommended_actions if ai_output else []),
        requires_human_review=blend["requires_human_review"]
        or bool(ai_output and ai_output.requires_human_review),
        deterministic_only=blend["deterministic_only"],
        model=(ai_output and settings.ai_model) or None,
        prompt_version=(ai_output and agents.risk_analyst.RISK_PROMPT.version) or None,
    )
    db.add(assessment)
    db.flush()
    db.commit()

    logger.info(
        "risk assessment stored",
        extra={
            "extra_fields": {
                "assessment_id": str(assessment.id),
                "finding_id": str(finding.id),
                "risk_level": assessment.risk_level,
                "final_score": assessment.final_score,
                "deterministic_score": assessment.deterministic_score,
                "ai_risk_score": assessment.ai_risk_score,
                "deterministic_only": assessment.deterministic_only,
                "coverage": signal_set.coverage,
            }
        },
    )
    return assessment


def latest(db: Session, finding_id: uuid.UUID) -> RiskAssessment | None:
    return db.execute(
        select(RiskAssessment)
        .where(RiskAssessment.finding_id == finding_id)
        .order_by(RiskAssessment.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def history(db: Session, finding_id: uuid.UUID, limit: int = 20) -> list[RiskAssessment]:
    return list(
        db.execute(
            select(RiskAssessment)
            .where(RiskAssessment.finding_id == finding_id)
            .order_by(RiskAssessment.created_at.desc())
            .limit(limit)
        ).scalars()
    )


def latest_for_assets(db: Session, asset_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[RiskAssessment]]:
    if not asset_ids:
        return {}
    rows = (
        db.execute(
            select(RiskAssessment)
            .where(RiskAssessment.asset_id.in_(asset_ids))
            .order_by(RiskAssessment.asset_id, RiskAssessment.created_at.desc())
        )
        .scalars()
        .all()
    )
    grouped: dict[uuid.UUID, list[RiskAssessment]] = {}
    for row in rows:
        grouped.setdefault(row.asset_id, []).append(row)
    return grouped


def to_dict(assessment: RiskAssessment, *, execution: AIExecution | None = None) -> dict[str, Any]:
    return {
        "id": str(assessment.id),
        "finding_id": str(assessment.finding_id),
        "asset_id": str(assessment.asset_id),
        "context_snapshot_id": str(assessment.context_snapshot_id)
        if assessment.context_snapshot_id
        else None,
        "policy_key": assessment.policy_key,
        "policy_version": assessment.policy_version,
        "cvss_score": float(assessment.cvss_score) if assessment.cvss_score is not None else None,
        "epss_score": float(assessment.epss_score) if assessment.epss_score is not None else None,
        "is_kev": assessment.is_kev,
        "risk_level": assessment.risk_level,
        "deterministic_score": assessment.deterministic_score,
        "ai_risk_score": assessment.ai_risk_score,
        "ai_risk_level": assessment.ai_risk_level,
        "final_score": assessment.final_score,
        "confidence": float(assessment.confidence) if assessment.confidence is not None else None,
        "deterministic_only": assessment.deterministic_only,
        "requires_human_review": assessment.requires_human_review,
        "summary": assessment.summary,
        "impact_analysis": assessment.impact_analysis,
        "exploitability_analysis": assessment.exploitability_analysis,
        "affected_components": assessment.affected_components,
        "signals": assessment.signals,
        "evidence": assessment.evidence,
        "missing_information": assessment.missing_information,
        "recommended_actions": assessment.recommended_actions,
        "model": assessment.model,
        "prompt_version": assessment.prompt_version,
        "created_at": assessment.created_at.isoformat() if assessment.created_at else None,
        "execution": None,
    }
