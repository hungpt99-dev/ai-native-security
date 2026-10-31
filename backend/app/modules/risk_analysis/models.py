"""Risk assessment persistence.

Append-only: a new assessment never overwrites an old one. Five different
notions of "how bad is this" are kept apart on purpose:

* ``cvss_score``               — the vendor/NVD score, copied as evidence.
* ``deterministic_score``      — platform signals, reproducible from ``signals``.
* ``ai_risk_score``            — the model's contextual judgement (nullable).
* ``final_score`` / ``risk_level`` — the configured policy combination.
* ``confidence``               — how much evidence the assessment rests on.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import RiskLevel
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_RISK_LEVEL_SQL = ",".join(f"'{level.value}'" for level in RiskLevel)


class RiskAssessment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "risk_assessments"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    context_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_context_snapshots.id", ondelete="SET NULL")
    )
    ai_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("ai_executions.id", ondelete="SET NULL")
    )
    policy_key: Mapped[str] = mapped_column(String(64), nullable=False, default="default-risk")
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")

    #: Evidence copied at assessment time so the row is self-contained.
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    epss_score: Mapped[float | None] = mapped_column(Numeric(5, 4))
    is_kev: Mapped[bool] = mapped_column(default=False)

    deterministic_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ai_risk_score: Mapped[int | None] = mapped_column(Integer)
    final_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default=RiskLevel.UNKNOWN.value)
    ai_risk_level: Mapped[str | None] = mapped_column(String(16))
    confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))

    summary: Mapped[str | None] = mapped_column(Text)
    impact_analysis: Mapped[str | None] = mapped_column(Text)
    exploitability_analysis: Mapped[str | None] = mapped_column(Text)
    reasoning: Mapped[str | None] = mapped_column(Text)

    signals: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    affected_components: Mapped[list[str]] = mapped_column(JSONB, default=list)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    missing_information: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    recommended_actions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    requires_human_review: Mapped[bool] = mapped_column(default=True)

    #: True when the AI part failed and only deterministic signals informed the
    #: score. Never presented as an AI assessment.
    deterministic_only: Mapped[bool] = mapped_column(default=False)
    model: Mapped[str | None] = mapped_column(String(96))
    prompt_version: Mapped[str | None] = mapped_column(String(16))

    __table_args__ = (
        CheckConstraint(f"risk_level IN ({_RISK_LEVEL_SQL})", name="risk_assessment_level"),
        CheckConstraint(
            "ai_risk_level IS NULL OR ai_risk_level IN (" + _RISK_LEVEL_SQL + ")",
            name="risk_assessment_ai_level",
        ),
        Index("ix_risk_assessments_finding_created", "finding_id", "created_at"),
        Index("ix_risk_assessments_asset_created", "asset_id", "created_at"),
        Index("ix_risk_assessments_level", "risk_level"),
        Index("ix_risk_assessments_score", "final_score"),
    )
