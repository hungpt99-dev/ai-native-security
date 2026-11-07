"""Incident, timeline and finding-link models.

An incident is the durable, human-owned unit of work. Events and findings attach
to it; nothing about it is inferred by a model. Severity/priority/risk are
computed deterministically from the attached evidence.
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
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import (
    INCIDENT_STATUSES,
    EventCategory,
    IncidentEventKind,
    IncidentPriority,
    IncidentStatus,
    Severity,
)
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_STATUS_SQL = ",".join(f"'{value}'" for value in INCIDENT_STATUSES)
_PRIORITY_SQL = ",".join(f"'{value}'" for value in IncidentPriority)
_SEVERITY_SQL = ",".join(f"'{value}'" for value in Severity)
_CATEGORY_SQL = ",".join(f"'{value}'" for value in EventCategory)
_KIND_SQL = ",".join(f"'{value}'" for value in IncidentEventKind)


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    #: Worst severity among attached evidence. Recomputed by the service, never
    #: lowered by an AI response.
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default=Severity.MEDIUM.value)
    priority: Mapped[str] = mapped_column(String(4), nullable=False, default=IncidentPriority.P3.value)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=IncidentStatus.OPEN.value)

    #: Primary domain of the incident (the category of the triggering event).
    category: Mapped[str | None] = mapped_column(String(24))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    #: Groups evidence that belongs together (rule + asset, or a composed key).
    #: Open incidents with the same key are reused instead of duplicated.
    correlation_key: Mapped[str] = mapped_column(String(250), nullable=False)
    detection_rule_slug: Mapped[str | None] = mapped_column(String(120))

    #: Deterministic score 0-100 from severity, asset criticality, exposure and
    #: threat-intelligence matches. AI never writes this column.
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    assigned_to: Mapped[str | None] = mapped_column(String(120))
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    __table_args__ = (
        CheckConstraint(f"status IN ({_STATUS_SQL})", name="incident_status"),
        CheckConstraint(f"priority IN ({_PRIORITY_SQL})", name="incident_priority"),
        CheckConstraint(f"severity IN ({_SEVERITY_SQL})", name="incident_severity"),
        CheckConstraint(
            f"category IS NULL OR category IN ({_CATEGORY_SQL})", name="incident_category"
        ),
        Index("ix_incidents_status_opened", "status", "opened_at"),
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_asset", "asset_id", "opened_at"),
        Index("ix_incidents_correlation", "correlation_key", "status"),
        Index("ix_incidents_opened", "opened_at"),
    )


class IncidentTimelineEntry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Append-only incident timeline.

    The timeline is the investigation record: who changed what, which event was
    attached, which AI report was produced. Rows are never updated.
    """

    __tablename__ = "incident_timeline"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False, default="system")
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        CheckConstraint(f"kind IN ({_KIND_SQL})", name="incident_timeline_kind"),
        Index("ix_incident_timeline_incident_created", "incident_id", "created_at"),
    )


class IncidentFinding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Explicit link between an incident and a finding (many-to-many).

    Findings are linked by deterministic correlation (same asset and CVE /
    same asset and time window), never by a model.
    """

    __tablename__ = "incident_findings"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    reason: Mapped[str] = mapped_column(String(120), nullable=False, default="manual")

    __table_args__ = (
        UniqueConstraint("incident_id", "finding_id", name="uq_incident_findings_pair"),
        Index("ix_incident_findings_finding", "finding_id"),
    )


class IncidentInvestigation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Append-only AI investigation of an incident.

    Separate from ``security_investigations`` (which is finding-scoped) because
    the evidence is a correlated event set, not a single vulnerability. Stored
    next to the evidence ids it cites; the status vocabulary is shared with
    finding investigations so operators learn one set of terms.
    """

    __tablename__ = "incident_investigations"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float | None] = mapped_column()
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    missing_information: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    next_actions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    attack_steps: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    ai_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("ai_executions.id", ondelete="SET NULL")
    )
    model: Mapped[str] = mapped_column(String(96), nullable=False, default="")
    prompt_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    prompt_version: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_incident_investigations_incident_created", "incident_id", "created_at"),
    )
