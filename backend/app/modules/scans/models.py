"""Scan and scanner-execution models."""

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
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import ScannerExecutionStatus, ScanStatus
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Scan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ScanStatus.PENDING.value
    )
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="MANUAL")
    branch: Mapped[str | None] = mapped_column(String(200))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    requested_by: Mapped[str | None] = mapped_column(String(120))

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[int | None] = mapped_column(Integer)

    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    info_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    error_message: Mapped[str | None] = mapped_column(Text)

    executions: Mapped[list[ScannerExecution]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="ScannerExecution.scanner"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','RUNNING','COMPLETED','FAILED','CANCELED')",
            name="scan_status",
        ),
        CheckConstraint("trigger IN ('MANUAL','SCHEDULED')", name="scan_trigger"),
        Index("ix_scans_asset_created", "asset_id", "created_at"),
        Index("ix_scans_status", "status"),
        # A repository may only have one active (PENDING/RUNNING) scan at a
        # time. This is enforced in the database, not just in service code.
        Index(
            "uq_scans_active_asset",
            "asset_id",
            unique=True,
            postgresql_where=text("status IN ('PENDING','RUNNING')"),
        ),
    )


class ScannerExecution(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scanner_executions"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    scanner: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ScannerExecutionStatus.PENDING.value
    )
    version: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    result_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    command: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    stdout_excerpt: Mapped[str | None] = mapped_column(Text)
    stderr_excerpt: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="executions")

    __table_args__ = (
        UniqueConstraint("scan_id", "scanner", name="uq_scanner_executions_scan_scanner"),
        CheckConstraint(
            "status IN ('PENDING','RUNNING','SUCCESS','FAILED','TIMED_OUT','SKIPPED')",
            name="scanner_execution_status",
        ),
        Index("ix_scanner_executions_scan", "scan_id"),
    )
