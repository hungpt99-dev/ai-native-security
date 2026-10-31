"""SBOM metadata and extracted package inventory models."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Sbom(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """SBOM metadata. Documents live in object storage, not in the database."""

    __tablename__ = "sboms"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    format: Mapped[str] = mapped_column(String(24), nullable=False, default="CYCLONEDX_JSON")
    spec_version: Mapped[str | None] = mapped_column(String(16))
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False, default="syft")
    tool_version: Mapped[str | None] = mapped_column(String(64))
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    package_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_type: Mapped[str | None] = mapped_column(String(64))

    packages: Mapped[list[SbomPackage]] = relationship(
        back_populates="sbom", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        Index("ix_sboms_asset_created", "asset_id", "created_at"),
        Index("ix_sboms_scan", "scan_id"),
    )


class SbomPackage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "sbom_packages"

    sbom_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    ecosystem: Mapped[str | None] = mapped_column(String(64))
    purl: Mapped[str | None] = mapped_column(String(500))
    license: Mapped[str | None] = mapped_column(Text)
    source_type: Mapped[str | None] = mapped_column(String(64))
    cpe: Mapped[str | None] = mapped_column(String(255))

    sbom: Mapped[Sbom] = relationship(back_populates="packages")

    __table_args__ = (
        Index("ix_sbom_packages_sbom", "sbom_id"),
        Index("ix_sbom_packages_name_version", "name", "version"),
        Index("ix_sbom_packages_ecosystem_name", "ecosystem", "name"),
    )
