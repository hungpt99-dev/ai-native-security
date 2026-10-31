"""Security knowledge layer: decisions, feedback, assistant transcripts.

Retrieval is SQL + PostgreSQL full-text for now. No vector database: there is no
concrete requirement that justifies one, and structured history answers the
questions the product asks ("what did we decide about this CVE last time").
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import DECISION_TYPES, FEEDBACK_VERDICTS
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_DECISION_SQL = ",".join(f"'{value}'" for value in DECISION_TYPES)
_VERDICT_SQL = ",".join(f"'{value}'" for value in FEEDBACK_VERDICTS)


class SecurityDecision(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Immutable record of a human (or explicitly labelled system) decision."""

    __tablename__ = "security_decisions"

    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE")
    )
    decision_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False, default="system")
    reason: Mapped[str | None] = mapped_column(Text)
    finding_status: Mapped[str | None] = mapped_column(String(24))
    remediation_status: Mapped[str | None] = mapped_column(String(24))
    risk_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_assessments.id", ondelete="SET NULL")
    )
    recommendation_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("remediation_recommendations.id", ondelete="SET NULL")
    )
    decision_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)

    __table_args__ = (
        CheckConstraint(f"decision_type IN ({_DECISION_SQL})", name="security_decision_type"),
        Index("ix_decisions_finding_created", "finding_id", "created_at"),
        Index("ix_decisions_type_created", "decision_type", "created_at"),
    )


class AIFeedback(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Human feedback on an AI artefact. Stored, never used to fine-tune."""

    __tablename__ = "ai_feedback"

    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE")
    )
    risk_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_assessments.id", ondelete="SET NULL")
    )
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_investigations.id", ondelete="SET NULL")
    )
    recommendation_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("remediation_recommendations.id", ondelete="SET NULL")
    )
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(120), nullable=False, default="api")

    __table_args__ = (
        CheckConstraint(f"verdict IN ({_VERDICT_SQL})", name="ai_feedback_verdict"),
        Index("ix_feedback_finding_created", "finding_id", "created_at"),
        Index("ix_feedback_verdict", "verdict"),
    )


class AssistantConversation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assistant_conversations"

    title: Mapped[str] = mapped_column(String(200), nullable=False, default="Security question")
    principal: Mapped[str] = mapped_column(String(120), nullable=False, default="api")
    message_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    messages: Mapped[list[AssistantMessage]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (Index("ix_assistant_conversations_principal", "principal", "created_at"),)


class AssistantMessage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assistant_messages"

    conversation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("assistant_conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_calls: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    tool_results: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    cited_finding_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    ai_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("ai_executions.id", ondelete="SET NULL")
    )

    conversation: Mapped[AssistantConversation] = relationship(back_populates="messages")

    __table_args__ = (
        Index("ix_assistant_messages_conversation_created", "conversation_id", "created_at"),
        CheckConstraint("role IN ('user','assistant','tool','system')", name="assistant_role"),
    )
