"""Threat intelligence indicators.

Values are normalized on write (lowercase domain, canonical IP, lowercase hash)
so matching is exact and does not depend on the producer's formatting. A
matching indicator never changes a scanner finding; it enriches an event and
contributes a documented risk signal.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import INDICATOR_SOURCES, INDICATOR_TYPES, Severity
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_TYPE_SQL = ",".join(f"'{value}'" for value in INDICATOR_TYPES)
_SOURCE_SQL = ",".join(f"'{value}'" for value in INDICATOR_SOURCES)
_SEVERITY_SQL = ",".join(f"'{value}'" for value in Severity)


class ThreatIndicator(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "threat_indicators"

    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Normalized value. Never a raw log line; see ``threat_intel.service``.
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="MANUAL")
    #: Where the indicator came from inside a feed (feed name, report id).
    source_ref: Mapped[str | None] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default=Severity.HIGH.value)
    #: 0-100 producer confidence. Used both for ordering and for the risk bonus;
    #: it is never invented by the platform.
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    description: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    __table_args__ = (
        CheckConstraint(f"indicator_type IN ({_TYPE_SQL})", name="threat_indicator_type"),
        CheckConstraint(f"source IN ({_SOURCE_SQL})", name="threat_indicator_source"),
        CheckConstraint(f"severity IN ({_SEVERITY_SQL})", name="threat_indicator_severity"),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="threat_indicator_confidence"),
        UniqueConstraint(
            "indicator_type", "value", "source", name="uq_threat_indicators_identity"
        ),
        Index("ix_threat_indicators_type_value", "indicator_type", "value"),
        Index("ix_threat_indicators_active", "active", "expires_at"),
        Index("ix_threat_indicators_source_ingested", "source", "ingested_at"),
    )


class ThreatIntelIngest(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Audit row per ingestion batch (who added what, how many, from where)."""

    __tablename__ = "threat_intel_ingests"

    source: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False, default="system")
    received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rejected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)

    __table_args__ = (Index("ix_threat_intel_ingests_created", "created_at"),)
