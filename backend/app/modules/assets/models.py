"""Asset inventory and repository credential models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AssetCredential(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Encrypted repository access token.

    The plaintext token is never stored: ``encrypted_secret`` holds a Fernet
    token and ``secret_hint`` only a masked suffix for display.
    """

    __tablename__ = "asset_credentials"

    label: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    secret_hint: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    assets: Mapped[list[Asset]] = relationship(back_populates="credential")


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: What this row describes. Repositories are the default so every existing
    #: row keeps its meaning; infrastructure and runtime assets reuse the same
    #: inventory instead of forking ownership/criticality into another table.
    kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="REPOSITORY", server_default="REPOSITORY"
    )
    #: Repository URL. NULL for non-repository assets.
    repo_url: Mapped[str | None] = mapped_column(String(500), unique=True, nullable=True)
    #: Provider-qualified identity for non-repository assets, e.g.
    #: ``docker://nginx:1.25``, ``host://api-prod-01``, ``aws://1234/role/x``.
    external_ref: Mapped[str | None] = mapped_column(String(500))
    #: Optional parent (service -> host, workload -> cluster, image -> service).
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(200), nullable=False, default="main")
    description: Mapped[str | None] = mapped_column(Text)
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("asset_credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    scan_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Independent cadence for infrastructure assessment (IaC/image). NULL uses
    #: the configured default.
    infra_scan_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_status: Mapped[str | None] = mapped_column(String(16))
    #: Last infrastructure assessment, kept separate from repository scans.
    last_infra_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_infra_scan_status: Mapped[str | None] = mapped_column(String(16))

    credential: Mapped[AssetCredential | None] = relationship(
        back_populates="assets", lazy="joined"
    )

    __table_args__ = (
        Index("ix_assets_provider", "provider"),
        Index("ix_assets_kind", "kind"),
        Index("ix_assets_monitoring_enabled", "monitoring_enabled"),
        Index("ix_assets_parent", "parent_asset_id"),
        # An external identity is unique per kind; NULLs (repositories) are
        # excluded so existing rows are unaffected.
        Index(
            "uq_assets_kind_external_ref",
            "kind",
            "external_ref",
            unique=True,
            postgresql_where=text("external_ref IS NOT NULL"),
        ),
    )
