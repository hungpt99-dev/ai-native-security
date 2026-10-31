"""Security knowledge layer: decisions, feedback and retrieval.

Retrieval is plain SQL (with PostgreSQL full-text where it helps). No vector
database is used: there is no requirement that justifies one, and the questions
the product asks are structured ("what did we decide about this rule before"),
not semantic search.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.enums import FeedbackVerdict
from app.core.logging import get_logger
from app.modules.findings.models import Finding
from app.modules.knowledge_base.models import AIFeedback, SecurityDecision
from app.modules.remediation.models import RemediationRecommendation

logger = get_logger(__name__)


def record_decision(
    db: Session,
    *,
    decision_type: str,
    actor: str,
    finding_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    reason: str | None = None,
    finding_status: str | None = None,
    remediation_status: str | None = None,
    risk_assessment_id: uuid.UUID | None = None,
    recommendation_id: uuid.UUID | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityDecision:
    decision = SecurityDecision(
        finding_id=finding_id,
        asset_id=asset_id,
        decision_type=decision_type,
        actor=actor,
        reason=reason,
        finding_status=finding_status,
        remediation_status=remediation_status,
        risk_assessment_id=risk_assessment_id,
        recommendation_id=recommendation_id,
        decision_metadata=metadata or {},
    )
    db.add(decision)
    db.flush()
    logger.info(
        "security decision recorded",
        extra={
            "extra_fields": {
                "decision_id": str(decision.id),
                "decision_type": decision_type,
                "finding_id": str(finding_id) if finding_id else None,
                "actor": actor,
            }
        },
    )
    return decision


def record_feedback(
    db: Session,
    *,
    verdict: str,
    actor: str,
    comment: str | None = None,
    finding_id: uuid.UUID | None = None,
    risk_assessment_id: uuid.UUID | None = None,
    investigation_id: uuid.UUID | None = None,
    recommendation_id: uuid.UUID | None = None,
) -> AIFeedback:
    verdict = verdict.upper()
    if verdict not in {value.value for value in FeedbackVerdict}:
        from app.core.errors import ValidationError

        raise ValidationError("Unknown feedback verdict", details={"verdict": verdict})
    row = AIFeedback(
        verdict=verdict,
        actor=actor,
        comment=comment,
        finding_id=finding_id,
        risk_assessment_id=risk_assessment_id,
        investigation_id=investigation_id,
        recommendation_id=recommendation_id,
    )
    db.add(row)
    db.flush()
    return row


def decisions_for_finding(db: Session, finding_id: uuid.UUID, limit: int = 20) -> list[SecurityDecision]:
    return list(
        db.execute(
            select(SecurityDecision)
            .where(SecurityDecision.finding_id == finding_id)
            .order_by(SecurityDecision.created_at.desc())
            .limit(limit)
        ).scalars()
    )


def feedback_for_finding(db: Session, finding_id: uuid.UUID, limit: int = 20) -> list[AIFeedback]:
    return list(
        db.execute(
            select(AIFeedback)
            .where(AIFeedback.finding_id == finding_id)
            .order_by(AIFeedback.created_at.desc())
            .limit(limit)
        ).scalars()
    )


def feedback_summary(db: Session) -> dict[str, int]:
    rows = db.execute(
        select(AIFeedback.verdict, func.count(AIFeedback.id)).group_by(AIFeedback.verdict)
    ).all()
    return {verdict: int(count) for verdict, count in rows}


def similar_history(db: Session, *, scanner: str, rule_id: str, limit: int = 5) -> dict[str, Any]:
    """Prior decisions/feedback for the same rule on other findings."""
    finding_ids = (
        db.execute(
            select(Finding.id).where(Finding.scanner == scanner, Finding.rule_id == rule_id).limit(200)
        )
        .scalars()
        .all()
    )
    if not finding_ids:
        return {"decisions": [], "feedback": []}
    decisions = (
        db.execute(
            select(SecurityDecision)
            .where(SecurityDecision.finding_id.in_(finding_ids))
            .order_by(SecurityDecision.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    feedback = (
        db.execute(
            select(AIFeedback)
            .where(AIFeedback.finding_id.in_(finding_ids))
            .order_by(AIFeedback.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return {
        "decisions": [
            {
                "decision_type": row.decision_type,
                "actor": row.actor,
                "reason": (row.reason or "")[:300],
                "at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in decisions
        ],
        "feedback": [
            {
                "verdict": row.verdict,
                "comment": (row.comment or "")[:300],
                "at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in feedback
        ],
    }


def remediation_success_history(
    db: Session, *, package_name: str | None, limit: int = 5
) -> list[dict[str, Any]]:
    if not package_name:
        return []
    rows = (
        db.execute(
            select(RemediationRecommendation)
            .where(RemediationRecommendation.target_package == package_name)
            .order_by(RemediationRecommendation.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "strategy": row.strategy,
            "status": row.status,
            "from_version": row.current_version,
            "to_version": row.recommended_version,
            "at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


def knowledge_for_finding(db: Session, finding: Finding) -> dict[str, Any]:
    """Compact prior-knowledge bundle used as extra context evidence."""
    return {
        "decisions": [
            {
                "type": row.decision_type,
                "actor": row.actor,
                "reason": (row.reason or "")[:200],
                "at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in decisions_for_finding(db, finding.id, limit=5)
        ],
        "feedback": [
            {
                "verdict": row.verdict,
                "comment": (row.comment or "")[:200],
            }
            for row in feedback_for_finding(db, finding.id, limit=5)
        ],
        "similar_rule_history": similar_history(db, scanner=finding.scanner, rule_id=finding.rule_id),
    }


def search(db: Session, query: str, limit: int = 10) -> dict[str, Any]:
    """Free-text retrieval over decisions and remediation proposals."""
    needle = f"%{query.strip()}%"
    if not query.strip():
        return {"decisions": [], "recommendations": []}
    decisions = (
        db.execute(
            select(SecurityDecision)
            .where(
                or_(
                    SecurityDecision.reason.ilike(needle),
                    SecurityDecision.decision_type.ilike(needle),
                )
            )
            .order_by(SecurityDecision.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    recommendations = (
        db.execute(
            select(RemediationRecommendation)
            .where(
                or_(
                    RemediationRecommendation.summary.ilike(needle),
                    RemediationRecommendation.target_package.ilike(needle),
                )
            )
            .order_by(RemediationRecommendation.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return {
        "decisions": [
            {
                "id": str(row.id),
                "type": row.decision_type,
                "actor": row.actor,
                "reason": (row.reason or "")[:300],
            }
            for row in decisions
        ],
        "recommendations": [
            {
                "id": str(row.id),
                "summary": row.summary,
                "status": row.status,
                "package": row.target_package,
            }
            for row in recommendations
        ],
    }
