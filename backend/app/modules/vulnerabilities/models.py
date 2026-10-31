"""Vulnerability intelligence models (OSV, NVD, CISA KEV).

A vulnerability record is keyed by ``(source, source_id)`` because identifiers
are not globally consistent: OSV entries may have no CVE at all, NVD entries
are CVE-centric, and KEV only flags CVEs. ``cve_id`` is therefore nullable and
used only for correlation.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
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

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Vulnerability(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerabilities"

    source: Mapped[str] = mapped_column(String(24), nullable=False)
    #: Identifier within the source (OSV id, CVE id or KEV cveID).
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)

    cve_id: Mapped[str | None] = mapped_column(String(32))
    osv_id: Mapped[str | None] = mapped_column(String(128))
    summary: Mapped[str | None] = mapped_column(String(1000))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_required_action: Mapped[str | None] = mapped_column(Text)
    source_payload_hash: Mapped[str | None] = mapped_column(String(64))

    references: Mapped[list[VulnerabilityReference]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan", passive_deletes=True
    )
    affected_packages: Mapped[list[VulnerabilityAffectedPackage]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        UniqueConstraint("source", "source_id", name="uq_vulnerabilities_source_source_id"),
        CheckConstraint(
            "source IN ('OSV','NVD','CISA_KEV')", name="vulnerability_source"
        ),
        Index("ix_vulnerabilities_cve", "cve_id"),
        Index("ix_vulnerabilities_severity", "severity"),
        Index("ix_vulnerabilities_is_kev", "is_kev"),
        Index("ix_vulnerabilities_modified", "modified_at"),
    )


class VulnerabilityReference(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerability_references"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    ref_type: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str | None] = mapped_column(String(32))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="references")

    __table_args__ = (
        Index("ix_vulnerability_references_vuln", "vulnerability_id"),
        UniqueConstraint("vulnerability_id", "url", name="uq_vuln_reference_vuln_url"),
    )


class VulnerabilityAffectedPackage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerability_affected_packages"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    ecosystem: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    purl: Mapped[str | None] = mapped_column(String(500))
    affected_versions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    fixed_versions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    version_ranges: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="affected_packages")

    __table_args__ = (
        Index("ix_vap_ecosystem_name", "ecosystem", "package_name"),
        Index("ix_vap_package_name", "package_name"),
        Index("ix_vap_vuln", "vulnerability_id"),
    )


class VulnerabilitySyncHistory(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerability_sync_history"

    source: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="RUNNING")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    records_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cursor: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(
            "status IN ('RUNNING','SUCCESS','FAILED','PARTIAL')", name="sync_status"
        ),
        Index("ix_vuln_sync_source_started", "source", "started_at"),
    )


class VulnerabilityEpss(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """EPSS exploitation probability for a CVE.

    Kept in its own table (not on ``vulnerabilities``) because the score is a
    daily time series keyed by CVE only, while vulnerability rows are keyed by
    ``(source, source_id)`` and several sources can share one CVE.
    """

    __tablename__ = "vulnerability_epss"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[float] = mapped_column(Numeric(5, 4), nullable=False)
    percentile: Mapped[float] = mapped_column(Numeric(5, 4), nullable=False, default=0)
    model_version: Mapped[str | None] = mapped_column(String(32))
    scored_date: Mapped[date | None] = mapped_column(Date)

    __table_args__ = (
        UniqueConstraint("cve_id", name="uq_vulnerability_epss_cve"),
        Index("ix_vulnerability_epss_score", "score"),
    )
