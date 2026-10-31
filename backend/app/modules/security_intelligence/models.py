"""Security context and asset-profile models.

Layer 2 of the platform: everything the AI layer is allowed to *know* about a
finding, frozen into a snapshot so an assessment can always be re-explained with
the exact context it saw.
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
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AssetSecurityProfile(TimestampMixin, Base):
    """Business context for an asset.

    Every field is nullable on purpose: the platform must be able to say "not
    configured" instead of inventing a criticality. NULL is reported by the
    context builder as missing information.
    """

    __tablename__ = "asset_security_profiles"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    criticality: Mapped[str | None] = mapped_column(String(16))
    environment: Mapped[str | None] = mapped_column(String(32))
    internet_exposed: Mapped[bool | None] = mapped_column(Boolean)
    business_importance: Mapped[str | None] = mapped_column(String(24))
    data_sensitivity: Mapped[str | None] = mapped_column(String(24))
    owner_team: Mapped[str | None] = mapped_column(String(120))
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(
            "criticality IS NULL OR criticality IN ('CRITICAL','HIGH','MEDIUM','LOW')",
            name="asset_profile_criticality",
        ),
        CheckConstraint(
            "environment IS NULL OR environment IN ('PRODUCTION','STAGING','DEVELOPMENT','TEST','INTERNAL')",
            name="asset_profile_environment",
        ),
        CheckConstraint(
            "business_importance IS NULL OR business_importance IN "
            "('MISSION_CRITICAL','IMPORTANT','STANDARD','LOW')",
            name="asset_profile_business_importance",
        ),
        CheckConstraint(
            "data_sensitivity IS NULL OR data_sensitivity IN "
            "('RESTRICTED','CONFIDENTIAL','INTERNAL','PUBLIC')",
            name="asset_profile_data_sensitivity",
        ),
    )


class AssetRepositoryMetadata(TimestampMixin, Base):
    """Deterministically derived repository facts (languages, manifests)."""

    __tablename__ = "asset_repository_metadata"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    default_branch: Mapped[str | None] = mapped_column(String(200))
    languages: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    frameworks: Mapped[list[str]] = mapped_column(JSONB, default=list)
    manifests: Mapped[list[str]] = mapped_column(JSONB, default=list)
    service_count: Mapped[int | None] = mapped_column()
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityContextSnapshot(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Immutable, versioned context for one finding at one point in time."""

    __tablename__ = "security_context_snapshots"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    context_version: Mapped[str] = mapped_column(String(24), nullable=False, default="1")
    builder_version: Mapped[str] = mapped_column(String(64), nullable=False, default="1")
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    missing_information: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)

    __table_args__ = (
        Index("ix_ctx_snapshot_finding_created", "finding_id", "created_at"),
        Index("ix_ctx_snapshot_asset_created", "asset_id", "created_at"),
    )
