"""Finding and finding-history models.

Findings are stored per asset and deduplicated by a stable fingerprint
computed from semantic identity (scanner, rule/vulnerability id, location,
package identity) rather than scanner-generated ids.
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
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import FindingStatus
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    #: Scan in which the finding was first detected.
    first_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    #: Most recent scan that still detected the finding.
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )

    scanner: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")

    file_path: Mapped[str | None] = mapped_column(String(1000))
    line_number: Mapped[int | None] = mapped_column(Integer)
    package_name: Mapped[str | None] = mapped_column(String(255))
    package_version: Mapped[str | None] = mapped_column(String(128))
    purl: Mapped[str | None] = mapped_column(String(500))

    cve_id: Mapped[str | None] = mapped_column(String(32))
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))

    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=FindingStatus.OPEN.value
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)

    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    history: Mapped[list[FindingHistory]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("asset_id", "fingerprint", name="uq_findings_asset_fingerprint"),
        CheckConstraint(
            "status IN ('OPEN','CONFIRMED','FALSE_POSITIVE','ACCEPTED_RISK','RESOLVED')",
            name="finding_status",
        ),
        CheckConstraint(
            "severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN')",
            name="finding_severity",
        ),
        Index("ix_findings_asset_status", "asset_id", "status"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_scanner", "scanner"),
        Index("ix_findings_cve", "cve_id"),
        Index("ix_findings_last_detected", "last_detected_at"),
    )


class FindingHistory(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "finding_history"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    event: Mapped[str] = mapped_column(String(32), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(24))
    to_status: Mapped[str | None] = mapped_column(String(24))
    actor: Mapped[str] = mapped_column(String(120), nullable=False, default="system")
    note: Mapped[str | None] = mapped_column(Text)

    finding: Mapped[Finding] = relationship(back_populates="history")

    __table_args__ = (Index("ix_finding_history_finding_created", "finding_id", "created_at"),)
