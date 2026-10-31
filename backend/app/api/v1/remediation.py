"""Remediation centre and verification endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.api.v1.ai import check_scope
from app.core.pagination import Page, PageParams, page_params
from app.database.session import get_db
from app.modules.remediation import service as remediation_service
from app.modules.verification import service as verification_service

router = APIRouter(tags=["remediation"])


class DecisionRequest(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class TransitionRequest(BaseModel):
    status: str = Field(pattern="^[A-Z_]+$", max_length=24)
    note: str | None = Field(default=None, max_length=2000)


@router.get("/remediations", response_model=Page[dict])
def list_remediations(
    db: Annotated[Session, Depends(get_db)],
    params: Annotated[PageParams, Depends(page_params)],
    principal: CurrentPrincipal,
    status: Annotated[str | None, Query()] = None,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
) -> Page[dict]:
    if asset_id is not None:
        check_scope(principal, asset_id)
    rows, total = remediation_service.list_recommendations(db, params, status=status, asset_id=asset_id)
    if principal.asset_scope is not None:
        rows = [row for row in rows if row.asset_id in principal.asset_scope]
    return Page.build([remediation_service.to_dict(row) for row in rows], total, params)


@router.get("/remediations/{recommendation_id}")
def get_recommendation(
    recommendation_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    recommendation = remediation_service.get_or_404(db, recommendation_id)
    check_scope(principal, recommendation.asset_id)
    payload = remediation_service.to_dict(recommendation)
    payload["verifications"] = [
        verification_service.to_dict(row)
        for row in verification_service.for_recommendation(db, recommendation_id)
    ]
    return payload


@router.post("/remediations/{recommendation_id}/approve")
def approve_recommendation(
    recommendation_id: uuid.UUID,
    payload: DecisionRequest,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    recommendation = remediation_service.get_or_404(db, recommendation_id)
    check_scope(principal, recommendation.asset_id)
    updated = remediation_service.approve(db, recommendation_id, actor=principal.subject, note=payload.note)
    return remediation_service.to_dict(updated)


@router.post("/remediations/{recommendation_id}/reject")
def reject_recommendation(
    recommendation_id: uuid.UUID,
    payload: DecisionRequest,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    recommendation = remediation_service.get_or_404(db, recommendation_id)
    check_scope(principal, recommendation.asset_id)
    if not payload.note:
        from app.core.errors import ValidationError

        raise ValidationError("A reason is required to reject a recommendation")
    updated = remediation_service.reject(db, recommendation_id, actor=principal.subject, note=payload.note)
    return remediation_service.to_dict(updated)


@router.post("/remediations/{recommendation_id}/verify")
def start_verification(
    recommendation_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    recommendation = remediation_service.get_or_404(db, recommendation_id)
    check_scope(principal, recommendation.asset_id)
    recommendation, scan = verification_service.request_verification(
        db, recommendation_id, actor=principal.subject
    )
    return {
        "recommendation": remediation_service.to_dict(recommendation),
        "scan": {
            "id": str(scan.id),
            "status": scan.status,
            "asset_id": str(scan.asset_id),
        },
        "note": (
            "Verification runs automatically when the scan completes; the result is "
            "derived only from scanner evidence."
        ),
    }


@router.post("/remediations/{recommendation_id}/transition")
def transition_recommendation(
    recommendation_id: uuid.UUID,
    payload: TransitionRequest,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    """Move a proposal along the lifecycle (e.g. VERIFIED → DEPLOYED → CLOSED).

    Only transitions allowed by ``ALLOWED_REMEDIATION_TRANSITIONS`` are accepted;
    approval and rejection have their own endpoints because they record a
    decision with a mandatory actor and reason.
    """
    recommendation = remediation_service.get_or_404(db, recommendation_id)
    check_scope(principal, recommendation.asset_id)
    updated = remediation_service.transition(
        db, recommendation, payload.status, actor=principal.subject, note=payload.note
    )
    db.commit()
    return remediation_service.to_dict(updated)


@router.get("/remediations/{recommendation_id}/verifications")
def list_verifications(
    recommendation_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> list[dict[str, Any]]:
    recommendation = remediation_service.get_or_404(db, recommendation_id)
    check_scope(principal, recommendation.asset_id)
    return [
        verification_service.to_dict(row)
        for row in verification_service.for_recommendation(db, recommendation_id)
    ]


@router.post("/verifications/{verification_id}/explain")
def explain_verification(
    verification_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    verification = verification_service.get_or_404(db, verification_id)
    check_scope(principal, verification.asset_id)
    updated = verification_service.explain(db, verification_id, principal=principal.subject)
    return verification_service.to_dict(updated)
