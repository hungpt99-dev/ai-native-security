"""Unified security event model and the detection rules that produce meaning.

Events arrive normalized from an external sensor (Falco, a Kubernetes audit log
exporter, an application log shipper) or through the generic ingestion API. The
platform stores the bounded, redacted original alongside a flattened
``normalized`` document because every later stage — rule matching, correlation,
anomaly baselines, AI evidence — must read the same fields.

Nothing here calls a model. Detection is deterministic; AI runs after a
correlated incident exists and only ever explains the evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import (
    DetectionRuleSource,
    DetectionRuleType,
    EventCategory,
    EventSource,
    SecurityEventStatus,
    Severity,
)
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_CATEGORY_SQL = ",".join(f"'{value}'" for value in EventCategory)
_SOURCE_SQL = ",".join(f"'{value}'" for value in EventSource)
_STATUS_SQL = ",".join(f"'{value}'" for value in SecurityEventStatus)
_SEVERITY_SQL = ",".join(f"'{value}'" for value in Severity)
_RULE_TYPE_SQL = ",".join(f"'{value}'" for value in DetectionRuleType)
_RULE_SOURCE_SQL = ",".join(f"'{value}'" for value in DetectionRuleSource)


class DetectionRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A deterministic detection rule.

    ``conditions`` is a small, explicit DSL rather than executable code:
    ``{"all": [{"field": "normalized.process", "op": "in", "value": [...]}]}``.
    No regex is executed against unbounded input, and every matched rule is
    recorded on the event it produced, so a detection can always be explained
    after the rule changes (``rule_version`` is snapshotted on the event).
    """

    __tablename__ = "detection_rules"

    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(24), nullable=False, default="RUNTIME")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default=Severity.MEDIUM.value)
    rule_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default=DetectionRuleType.SIGNATURE.value
    )
    source: Mapped[str] = mapped_column(
        String(16), nullable=False, default=DetectionRuleSource.BUILTIN.value
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    #: Field conditions. Empty/None means "match every event of this category"
    #: (used by anomaly-derived rules, which are created by the job itself).
    conditions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    #: Optional window aggregation: {"count": 10, "window_seconds": 300,
    #: "group_by": ["normalized.remote_ip"]}.
    threshold: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    #: Create (or attach to) an incident when this rule matches.
    create_incident: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    incident_priority: Mapped[str | None] = mapped_column(String(4))

    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False, default="system")

    __table_args__ = (
        CheckConstraint(f"category IN ({_CATEGORY_SQL})", name="detection_rule_category"),
        CheckConstraint(f"severity IN ({_SEVERITY_SQL})", name="detection_rule_severity"),
        CheckConstraint(f"rule_type IN ({_RULE_TYPE_SQL})", name="detection_rule_type"),
        CheckConstraint(f"source IN ({_RULE_SOURCE_SQL})", name="detection_rule_source"),
        CheckConstraint(
            "incident_priority IS NULL OR incident_priority IN ('P1','P2','P3','P4')",
            name="detection_rule_priority",
        ),
        Index("ix_detection_rules_enabled", "enabled"),
        Index("ix_detection_rules_category", "category"),
    )


class SecurityEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One deduplicated security event.

    Identity is ``fingerprint`` — derived from source, event type, asset, rule
    and the primary entity (process, command line, file, remote address). A
    repeated occurrence updates ``occurrence_count``/``last_seen_at`` instead of
    creating a row per log line, which is what makes correlation and AI evidence
    affordable.
    """

    __tablename__ = "security_events"

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default=EventSource.GENERIC.value)
    #: Provider-side identifier when the sensor supplies one (Falco uuid, audit
    #: log id). Used for exact replay detection, never as identity.
    source_event_id: Mapped[str | None] = mapped_column(String(200))
    event_type: Mapped[str] = mapped_column(String(160), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default=Severity.MEDIUM.value)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=SecurityEventStatus.OPEN.value
    )

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL")
    )
    detection_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="SET NULL")
    )
    #: Rule identity as it was when the event was produced. A rule can be edited
    #: or disabled later; the event must still explain itself.
    rule_slug: Mapped[str | None] = mapped_column(String(120))
    rule_version: Mapped[int | None] = mapped_column(Integer)

    #: Deterministic risk contribution (0-100), never an AI judgement.
    risk_score: Mapped[int | None] = mapped_column(Integer)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    #: Bounded, redacted source payload. Truncation is recorded in
    #: ``enrichment.raw_truncated`` so a consumer never assumes completeness.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    normalized: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    #: Extracted indicators ([{"type": "IP", "value": "..."}]) for threat intel.
    indicators: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    #: Asset resolution, dedupe counts, threat matches, threshold results.
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        CheckConstraint(f"category IN ({_CATEGORY_SQL})", name="security_event_category"),
        CheckConstraint(f"source IN ({_SOURCE_SQL})", name="security_event_source"),
        CheckConstraint(f"status IN ({_STATUS_SQL})", name="security_event_status"),
        CheckConstraint(f"severity IN ({_SEVERITY_SQL})", name="security_event_severity"),
        Index("ix_security_events_last_seen", "last_seen_at"),
        Index("ix_security_events_category_seen", "category", "last_seen_at"),
        Index("ix_security_events_asset_seen", "asset_id", "last_seen_at"),
        Index("ix_security_events_incident", "incident_id"),
        Index("ix_security_events_status_seen", "status", "last_seen_at"),
        Index("ix_security_events_severity", "severity"),
        Index("ix_security_events_source", "source"),
        Index("ix_security_events_rule", "rule_slug"),
        # One event row per (source, provider event id) when an id is supplied:
        # a sensor retry must not double-count an occurrence.
        Index(
            "uq_security_events_source_event_id",
            "source",
            "source_event_id",
            unique=True,
            postgresql_where=text("source_event_id IS NOT NULL"),
        ),
    )


class SecurityEventNote(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Analyst notes attached to an event (append-only)."""

    __tablename__ = "security_event_notes"

    event_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False
    )
    author: Mapped[str] = mapped_column(String(120), nullable=False, default="system")
    body: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (Index("ix_security_event_notes_event", "event_id", "created_at"),)
