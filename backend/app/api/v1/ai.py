"""AI platform API: health, overview, ledger, prompts, policies, assistant, asset profiles."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal, Principal
from app.core.enums import ACTIVE_FINDING_STATUSES, RemediationStatus
from app.core.errors import AuthorizationError
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.ai.models import AIExecution
from app.modules.ai.prompts import list_prompts
from app.modules.ai.providers.registry import provider_status
from app.modules.ai.services import assistant as assistant_service
from app.modules.ai.services import budgets
from app.modules.ai.services.executions import to_dict as execution_to_dict
from app.modules.assets.models import Asset
from app.modules.findings.models import Finding
from app.modules.remediation.models import RemediationRecommendation
from app.modules.risk_analysis.models import RiskAssessment
from app.modules.security_intelligence.models import AssetSecurityProfile
from app.modules.security_policies import service as policies_service

router = APIRouter(prefix="/ai", tags=["ai"])


class SecurityProfileUpdate(BaseModel):
    criticality: str | None = Field(default=None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    environment: str | None = Field(default=None, pattern="^(PRODUCTION|STAGING|DEVELOPMENT|TEST|INTERNAL)$")
    internet_exposed: bool | None = None
    business_importance: str | None = Field(
        default=None, pattern="^(MISSION_CRITICAL|IMPORTANT|STANDARD|LOW)$"
    )
    data_sensitivity: str | None = Field(default=None, pattern="^(RESTRICTED|CONFIDENTIAL|INTERNAL|PUBLIC)$")
    owner_team: str | None = Field(default=None, max_length=120)
    notes: str | None = Field(default=None, max_length=4000)


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    conversation_id: uuid.UUID | None = None


def check_scope(principal: Principal, asset_id: uuid.UUID) -> None:
    if principal.asset_scope is not None and asset_id not in principal.asset_scope:
        raise AuthorizationError("Asset is outside the caller's scope", details={"asset_id": str(asset_id)})


@router.get("/health")
def ai_health(db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal) -> dict[str, Any]:
    status = provider_status()
    status["budget"] = budgets.usage_summary(db)
    status["prompts"] = len(list_prompts())
    return status


@router.get("/overview")
def ai_overview(db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal) -> dict[str, Any]:
    """AI security overview for the dashboard."""
    scope = principal.asset_scope
    latest = (
        select(
            RiskAssessment.asset_id,
            func.max(RiskAssessment.final_score).label("max_score"),
            func.count(RiskAssessment.id).label("assessments"),
        )
        .group_by(RiskAssessment.asset_id)
        .subquery()
    )
    asset_stmt = (
        select(Asset.id, Asset.name, Asset.repo_url, latest.c.max_score, latest.c.assessments)
        .join(latest, latest.c.asset_id == Asset.id)
        .order_by(latest.c.max_score.desc())
        .limit(5)
    )
    if scope is not None:
        asset_stmt = asset_stmt.where(Asset.id.in_(list(scope)))
    top_assets = [
        {
            "asset_id": str(row[0]),
            "name": row[1],
            "repo_url": row[2],
            "highest_final_score": int(row[3] or 0),
            "assessments": int(row[4] or 0),
        }
        for row in db.execute(asset_stmt).all()
    ]

    critical_stmt = (
        select(RiskAssessment, Finding.title, Finding.severity, Asset.name)
        .join(Finding, Finding.id == RiskAssessment.finding_id)
        .join(Asset, Asset.id == RiskAssessment.asset_id)
        .where(RiskAssessment.risk_level.in_(["CRITICAL", "HIGH"]))
        .where(Finding.status.in_(ACTIVE_FINDING_STATUSES))
        .order_by(RiskAssessment.final_score.desc())
        .limit(10)
    )
    if scope is not None:
        critical_stmt = critical_stmt.where(RiskAssessment.asset_id.in_(list(scope)))
    critical = [
        {
            "assessment_id": str(row[0].id),
            "finding_id": str(row[0].finding_id),
            "asset_id": str(row[0].asset_id),
            "asset_name": row[3],
            "title": row[1],
            "severity": row[2],
            "risk_level": row[0].risk_level,
            "final_score": row[0].final_score,
            "confidence": float(row[0].confidence) if row[0].confidence is not None else None,
            "deterministic_only": row[0].deterministic_only,
            "requires_human_review": row[0].requires_human_review,
            "created_at": row[0].created_at.isoformat() if row[0].created_at else None,
        }
        for row in db.execute(critical_stmt).all()
    ]

    review_stmt = select(func.count(RiskAssessment.id)).where(RiskAssessment.requires_human_review.is_(True))
    if scope is not None:
        review_stmt = review_stmt.where(RiskAssessment.asset_id.in_(list(scope)))
    needs_review = int(db.execute(review_stmt).scalar_one())

    pending_stmt = select(func.count(RemediationRecommendation.id)).where(
        RemediationRecommendation.status.in_(
            [
                RemediationStatus.AWAITING_APPROVAL.value,
                RemediationStatus.APPROVED.value,
                RemediationStatus.VALIDATING.value,
            ]
        )
    )
    if scope is not None:
        pending_stmt = pending_stmt.where(RemediationRecommendation.asset_id.in_(list(scope)))
    pending = int(db.execute(pending_stmt).scalar_one())

    unverified_stmt = select(func.count(RemediationRecommendation.id)).where(
        RemediationRecommendation.status.in_(
            [RemediationStatus.AWAITING_APPROVAL.value, RemediationStatus.APPROVED.value]
        )
    )
    if scope is not None:
        unverified_stmt = unverified_stmt.where(RemediationRecommendation.asset_id.in_(list(scope)))
    unverified = int(db.execute(unverified_stmt).scalar_one())

    return {
        "provider": provider_status(),
        "budget": budgets.usage_summary(db),
        "top_risk_assets": top_assets,
        "critical_findings": critical,
        "needs_review": needs_review,
        "remediation_pending": pending,
        "unverified_proposals": unverified,
    }


@router.get("/executions", response_model=Page[dict])
def list_executions(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    kind: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    finding_id: Annotated[uuid.UUID | None, Query()] = None,
) -> Page[dict]:
    stmt = select(AIExecution)
    if kind:
        stmt = stmt.where(AIExecution.kind == kind.upper())
    if status:
        stmt = stmt.where(AIExecution.status == status.upper())
    if finding_id:
        stmt = stmt.where(AIExecution.finding_id == finding_id)
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = (
        db.execute(stmt.order_by(AIExecution.created_at.desc()).limit(params.page_size).offset(params.offset))
        .scalars()
        .all()
    )
    return Page.build([execution_to_dict(row) for row in rows], total, params)


@router.get("/prompts")
def prompts(principal: CurrentPrincipal) -> list[dict[str, Any]]:
    return list_prompts()


@router.get("/policies")
def policies(
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    kind: Annotated[str | None, Query()] = None,
) -> list[dict[str, Any]]:
    rows = policies_service.list_policies(db, kind=kind)
    return [
        {
            "id": str(row.id),
            "key": row.key,
            "version": row.version,
            "kind": row.kind,
            "name": row.name,
            "description": row.description,
            "active": row.active,
            "is_default": row.is_default,
            "priority": row.priority,
            "config": row.config,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


# ------------------------------------------------------------------ assistant
@router.post("/assistant/ask")
def assistant_ask(
    payload: AskRequest,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    reply = assistant_service.ask(
        db,
        question=payload.question,
        principal=principal.subject,
        conversation_id=payload.conversation_id,
        asset_scope=principal.asset_scope,
    )
    return reply.as_dict()


@router.get("/assistant/conversations/{conversation_id}")
def assistant_conversation(
    conversation_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    conversation = assistant_service.get_conversation(db, conversation_id)
    if conversation.principal != principal.subject and conversation.principal != "anonymous":
        raise AuthorizationError("Conversation belongs to another principal")
    messages = assistant_service.history(db, conversation_id)
    return {
        "id": str(conversation.id),
        "title": conversation.title,
        "principal": conversation.principal,
        "messages": [
            {
                "id": str(message.id),
                "role": message.role,
                "content": message.content,
                "tool_calls": message.tool_calls,
                "tool_results": message.tool_results,
                "cited_finding_ids": message.cited_finding_ids,
                "created_at": message.created_at.isoformat() if message.created_at else None,
            }
            for message in messages
        ],
    }


# --------------------------------------------------------------- asset profile
@router.get("/assets/{asset_id}/security-profile")
def get_security_profile(
    asset_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    check_scope(principal, asset_id)
    profile = db.get(AssetSecurityProfile, asset_id)
    if profile is None:
        return {
            "asset_id": str(asset_id),
            "configured": False,
            "criticality": None,
            "environment": None,
            "internet_exposed": None,
            "business_importance": None,
            "data_sensitivity": None,
            "owner_team": None,
            "notes": None,
        }
    return {
        "asset_id": str(asset_id),
        "configured": True,
        "criticality": profile.criticality,
        "environment": profile.environment,
        "internet_exposed": profile.internet_exposed,
        "business_importance": profile.business_importance,
        "data_sensitivity": profile.data_sensitivity,
        "owner_team": profile.owner_team,
        "notes": profile.notes,
    }


@router.put("/assets/{asset_id}/security-profile")
def update_security_profile(
    asset_id: uuid.UUID,
    payload: SecurityProfileUpdate,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    check_scope(principal, asset_id)
    asset = db.get(Asset, asset_id)
    if asset is None:
        from app.core.errors import NotFoundError

        raise NotFoundError("Asset not found", details={"asset_id": str(asset_id)})
    profile = db.get(AssetSecurityProfile, asset_id)
    if profile is None:
        profile = AssetSecurityProfile(asset_id=asset_id)
        db.add(profile)
    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(profile, key, value)
    db.commit()
    return {
        "asset_id": str(asset_id),
        "configured": True,
        **{
            key: getattr(profile, key)
            for key in (
                "criticality",
                "environment",
                "internet_exposed",
                "business_importance",
                "data_sensitivity",
                "owner_team",
                "notes",
            )
        },
    }
