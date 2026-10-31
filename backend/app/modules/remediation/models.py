"""Remediation recommendations (proposals only — never applied by the platform)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import (
    REMEDIATION_STATUSES,
    REMEDIATION_STRATEGIES,
    RemediationStatus,
    RemediationStrategy,
)
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_STRATEGY_SQL = ",".join(f"'{value}'" for value in REMEDIATION_STRATEGIES)
_STATUS_SQL = ",".join(f"'{value}'" for value in REMEDIATION_STATUSES)


class RemediationRecommendation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "remediation_recommendations"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_investigations.id", ondelete="SET NULL")
    )
    risk_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_assessments.id", ondelete="SET NULL")
    )
    context_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_context_snapshots.id", ondelete="SET NULL")
    )
    ai_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("ai_executions.id", ondelete="SET NULL")
    )

    strategy: Mapped[str] = mapped_column(
        String(32), nullable=False, default=RemediationStrategy.MITIGATION.value
    )
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=RemediationStatus.REMEDIATION_PROPOSED.value,
    )
    summary: Mapped[str | None] = mapped_column(Text)
    reasoning: Mapped[str | None] = mapped_column(Text)

    target_package: Mapped[str | None] = mapped_column(String(255))
    current_version: Mapped[str | None] = mapped_column(String(128))
    recommended_version: Mapped[str | None] = mapped_column(String(128))
    #: True when ``recommended_version`` came from authoritative vulnerability
    #: data (and was re-checked deterministically), false otherwise.
    version_verified: Mapped[bool] = mapped_column(default=False)

    patch: Mapped[str | None] = mapped_column(Text)
    patch_format: Mapped[str | None] = mapped_column(String(32))
    changes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    breaking_change_risks: Mapped[list[str]] = mapped_column(JSONB, default=list)
    recommended_tests: Mapped[list[str]] = mapped_column(JSONB, default=list)
    expected_security_improvement: Mapped[str | None] = mapped_column(Text)
    missing_information: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)

    requires_human_approval: Mapped[bool] = mapped_column(default=True)
    approved_by: Mapped[str | None] = mapped_column(String(120))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejected_reason: Mapped[str | None] = mapped_column(Text)

    model: Mapped[str | None] = mapped_column(String(96))
    prompt_version: Mapped[str | None] = mapped_column(String(16))

    __table_args__ = (
        CheckConstraint(f"strategy IN ({_STRATEGY_SQL})", name="remediation_strategy"),
        CheckConstraint(f"status IN ({_STATUS_SQL})", name="remediation_status"),
        Index("ix_remediation_finding_created", "finding_id", "created_at"),
        Index("ix_remediation_status_created", "status", "created_at"),
        Index("ix_remediation_asset", "asset_id"),
    )
