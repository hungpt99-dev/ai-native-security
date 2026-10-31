"""Deterministic remediation verification records.

Every field that decides the status comes from scanner/DB evidence, never from a
model. The optional AI explanation is stored separately and cannot change
``status``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import VERIFICATION_STATUSES, VerificationStatus
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_STATUS_SQL = ",".join(f"'{value}'" for value in VERIFICATION_STATUSES)


class RemediationVerification(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "remediation_verifications"

    recommendation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("remediation_recommendations.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    original_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    verification_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )

    status: Mapped[str] = mapped_column(String(24), nullable=False, default=VerificationStatus.PENDING.value)
    before_version: Mapped[str | None] = mapped_column(String(128))
    after_version: Mapped[str | None] = mapped_column(String(128))
    finding_present_after: Mapped[bool | None] = mapped_column()
    package_present_after: Mapped[bool | None] = mapped_column()
    new_findings_count: Mapped[int | None] = mapped_column()
    policy_result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    notes: Mapped[str | None] = mapped_column(Text)

    #: Optional AI explanation of the deterministic result. Labelled as such.
    ai_explanation: Mapped[str | None] = mapped_column(Text)
    ai_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("ai_executions.id", ondelete="SET NULL")
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(f"status IN ({_STATUS_SQL})", name="verification_status"),
        Index("ix_verifications_recommendation_created", "recommendation_id", "created_at"),
        Index("ix_verifications_finding_created", "finding_id", "created_at"),
        Index("ix_verifications_status", "status"),
    )
