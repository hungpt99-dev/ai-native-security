"""Finding-scoped AI endpoints: context, risk, investigation, remediation, verification."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal, Principal
from app.api.v1.ai import check_scope
from app.core.errors import NotFoundError
from app.database.session import get_db
from app.modules.ai.services import investigations as investigations_service
from app.modules.findings import service as findings_service
from app.modules.remediation import service as remediation_service
from app.modules.risk_analysis import service as risk_service
from app.modules.security_intelligence.context_builder import SecurityContextBuilder
from app.modules.security_intelligence.models import SecurityContextSnapshot
from app.modules.verification import service as verification_service

router = APIRouter(prefix="/findings", tags=["ai"])


def _finding_or_404(db: Session, finding_id: uuid.UUID, principal: Principal):
    finding = findings_service.get_finding_or_404(db, finding_id)
    check_scope(principal, finding.asset_id)
    return finding


# ------------------------------------------------------------------- context
@router.get("/{finding_id}/security-context")
def latest_context(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    from sqlalchemy import select

    _finding_or_404(db, finding_id, principal)
    snapshot = db.execute(
        select(SecurityContextSnapshot)
        .where(SecurityContextSnapshot.finding_id == finding_id)
        .order_by(SecurityContextSnapshot.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if snapshot is None:
        raise NotFoundError("No security context has been built for this finding")
    return {
        "snapshot_id": str(snapshot.id),
        "finding_id": str(snapshot.finding_id),
        "context_version": snapshot.context_version,
        "builder_version": snapshot.builder_version,
        "evidence_hash": snapshot.evidence_hash,
        "missing_information": snapshot.missing_information,
        "payload": snapshot.payload,
        "created_at": snapshot.created_at.isoformat() if snapshot.created_at else None,
    }


@router.post("/{finding_id}/security-context")
def build_context(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    _finding_or_404(db, finding_id, principal)
    context, snapshot = SecurityContextBuilder().build_and_persist(db, finding_id)
    db.commit()
    return {
        "snapshot_id": str(snapshot.id),
        "evidence_hash": snapshot.evidence_hash,
        "evidence_count": len(context.evidence),
        "missing_information": [item.model_dump(mode="json") for item in context.missing_information],
        "payload": snapshot.payload,
        "created_at": snapshot.created_at.isoformat() if snapshot.created_at else None,
    }


# ---------------------------------------------------------------------- risk
@router.post("/{finding_id}/risk-assessment")
def assess_risk(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
    use_ai: Annotated[
        bool, Query(description="Allow a model call; deterministic scoring always runs")
    ] = True,
) -> dict[str, Any]:
    _finding_or_404(db, finding_id, principal)
    assessment = risk_service.assess(db, finding_id, principal=principal.subject, use_ai=use_ai)
    return risk_service.to_dict(assessment)


@router.get("/{finding_id}/risk-assessments")
def list_risk_assessments(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> list[dict[str, Any]]:
    _finding_or_404(db, finding_id, principal)
    return [risk_service.to_dict(row) for row in risk_service.history(db, finding_id)]


# -------------------------------------------------------------- investigation
@router.post("/{finding_id}/investigation")
def investigate(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    _finding_or_404(db, finding_id, principal)
    investigation = investigations_service.investigate(db, finding_id, principal=principal.subject)
    evidence = investigations_service.evidence_for(db, investigation.id)
    return investigations_service.to_dict(investigation, evidence=evidence)


@router.get("/{finding_id}/investigations")
def list_investigations(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> list[dict[str, Any]]:
    _finding_or_404(db, finding_id, principal)
    rows = investigations_service.history(db, finding_id)
    return [
        investigations_service.to_dict(row, evidence=investigations_service.evidence_for(db, row.id))
        for row in rows
    ]


# ---------------------------------------------------------------- remediation
@router.post("/{finding_id}/remediation")
def propose_remediation(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    _finding_or_404(db, finding_id, principal)
    recommendation = remediation_service.propose(db, finding_id, principal=principal.subject)
    return remediation_service.to_dict(recommendation)


@router.get("/{finding_id}/remediations")
def list_remediations(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> list[dict[str, Any]]:
    _finding_or_404(db, finding_id, principal)
    return [remediation_service.to_dict(row) for row in remediation_service.for_finding(db, finding_id)]


# --------------------------------------------------------------- verification
@router.get("/{finding_id}/verifications")
def list_verifications(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: CurrentPrincipal,
) -> list[dict[str, Any]]:
    _finding_or_404(db, finding_id, principal)
    return [
        verification_service.to_dict(row) for row in verification_service.history_for_finding(db, finding_id)
    ]
