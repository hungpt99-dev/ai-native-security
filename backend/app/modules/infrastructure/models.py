"""Infrastructure assessment models.

One row per assessment of an IaC path or container image. Findings produced by
these scanners are written through the same ``findings`` pipeline as repository
scans, so triage, risk and remediation do not fork.
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
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import INFRA_SCAN_STATUSES, INFRA_SCANNERS, INFRA_TARGET_KINDS
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_STATUS_SQL = ",".join(f"'{value}'" for value in INFRA_SCAN_STATUSES)
_TARGET_SQL = ",".join(f"'{value}'" for value in INFRA_TARGET_KINDS)
_SCANNER_SQL = ",".join(f"'{value}'" for value in INFRA_SCANNERS)


class InfrastructureScan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "infrastructure_scans"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE")
    )
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Repository URL, image reference or config path that was assessed.
    target_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    scanner: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    triggered_by: Mapped[str] = mapped_column(String(32), nullable=False, default="MANUAL")
    requested_by: Mapped[str | None] = mapped_column(String(120))
    commit_sha: Mapped[str | None] = mapped_column(String(64))

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[int | None] = mapped_column(Integer)

    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    error_message: Mapped[str | None] = mapped_column(Text)
    scanner_version: Mapped[str | None] = mapped_column(String(64))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    __table_args__ = (
        CheckConstraint(f"status IN ({_STATUS_SQL})", name="infrastructure_scan_status"),
        CheckConstraint(f"target_kind IN ({_TARGET_SQL})", name="infrastructure_scan_target"),
        CheckConstraint(f"scanner IN ({_SCANNER_SQL})", name="infrastructure_scan_scanner"),
        Index("ix_infrastructure_scans_asset_created", "asset_id", "created_at"),
        Index("ix_infrastructure_scans_status", "status"),
        Index("ix_infrastructure_scans_target", "target_kind", "target_ref"),
        # One active assessment per target; concurrent requests are refused by
        # the database, not just by a race-prone SELECT in the service.
        Index(
            "uq_infrastructure_scans_active_target",
            "target_kind",
            "target_ref",
            "scanner",
            unique=True,
            postgresql_where=text("status IN ('PENDING','RUNNING')"),
        ),
    )
