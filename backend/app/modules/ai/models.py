"""AI execution ledger, investigations and their evidence.

The ledger is the audit backbone of the AI layer: one row per model call, on
success *and* on failure. It never stores prompts, evidence text or secrets —
only identifiers, hashes, usage and cost.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    INVESTIGATION_STATUSES,
    AIExecutionStatus,
    InvestigationStatus,
)
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_AI_STATUSES = tuple(status.value for status in AIExecutionStatus)
_AI_STATUS_SQL = ",".join(f"'{status}'" for status in _AI_STATUSES)
_INVESTIGATION_SQL = ",".join(f"'{status}'" for status in INVESTIGATION_STATUSES)


class AIExecution(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ai_executions"

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=AIExecutionStatus.RUNNING.value)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    model: Mapped[str] = mapped_column(String(96), nullable=False, default="")

    prompt_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    prompt_version: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    prompt_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    schema_id: Mapped[str | None] = mapped_column(String(64))
    schema_version: Mapped[str | None] = mapped_column(String(16))

    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="SET NULL")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    context_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_context_snapshots.id", ondelete="SET NULL")
    )
    principal: Mapped[str] = mapped_column(String(120), nullable=False, default="system")

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    input_chars: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[float | None] = mapped_column(Numeric(12, 6))
    request_id: Mapped[str | None] = mapped_column(String(128))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    execution_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    __table_args__ = (
        CheckConstraint(f"status IN ({_AI_STATUS_SQL})", name="ai_execution_status"),
        Index("ix_ai_executions_created", "created_at"),
        Index("ix_ai_executions_kind_created", "kind", "created_at"),
        Index("ix_ai_executions_finding_created", "finding_id", "created_at"),
        Index("ix_ai_executions_status", "status"),
    )


class SecurityInvestigation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One investigation run of the AI security analyst for a finding."""

    __tablename__ = "security_investigations"

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
    risk_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_assessments.id", ondelete="SET NULL")
    )

    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=InvestigationStatus.INCONCLUSIVE.value
    )
    summary: Mapped[str | None] = mapped_column(Text)
    impact_analysis: Mapped[str | None] = mapped_column(Text)
    exploitability_analysis: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    missing_information: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    next_steps: Mapped[list[str]] = mapped_column(JSONB, default=list)
    answers: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    workflow_name: Mapped[str] = mapped_column(String(64), nullable=False, default="investigation")
    workflow_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")
    model: Mapped[str] = mapped_column(String(96), nullable=False, default="")
    prompt_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    prompt_version: Mapped[str] = mapped_column(String(16), nullable=False, default="")

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)

    evidence: Mapped[list[InvestigationEvidence]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        CheckConstraint(f"status IN ({_INVESTIGATION_SQL})", name="investigation_status"),
        Index("ix_investigations_finding_created", "finding_id", "created_at"),
        Index("ix_investigations_status_created", "status", "created_at"),
    )


class InvestigationEvidence(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single cited piece of evidence.

    ``evidence_key`` is the stable id the model is asked to cite (``E1``, ``E2``,
    …) so output validation can reject references that were never provided.
    """

    __tablename__ = "investigation_evidence"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("security_investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_key: Mapped[str] = mapped_column(String(16), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    locator: Mapped[str | None] = mapped_column(String(1000))
    excerpt: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    evidence_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)

    investigation: Mapped[SecurityInvestigation] = relationship(back_populates="evidence")

    __table_args__ = (
        Index("ix_investigation_evidence_investigation", "investigation_id"),
        Index("ix_investigation_evidence_key", "investigation_id", "evidence_key"),
    )
