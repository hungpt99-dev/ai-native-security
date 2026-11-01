"""SBOM metadata, extracted package inventory and lifecycle monitoring models."""

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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import SbomGenerationStatus, SbomSnapshotReason
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Sbom(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An immutable SBOM snapshot.

    The document lives in object storage; the row carries provenance. Four
    different identifiers are kept apart on purpose:

    * ``sha256`` — checksum of the stored document. Integrity only.
    * ``dependency_fingerprint`` — hash of the resolved component inventory
      (ecosystem/name/version or purl). Two documents can differ byte-wise and
      still describe the same composition.
    * ``manifest_fingerprint`` — hash of the dependency manifests, lockfiles and
      build configuration that were present in the workspace.
    * ``commit_sha`` — the Git state the workspace was checked out at.

    They answer different questions ("was the file altered", "did the resolved
    graph change", "did the declared inputs change", "what was built") and are
    never substituted for one another.
    """

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

    # ----------------------------------------------------------- provenance
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    branch: Mapped[str | None] = mapped_column(String(200))
    #: Hash of the resolved component inventory this snapshot recorded.
    dependency_fingerprint: Mapped[str | None] = mapped_column(String(64))
    #: Hash of the dependency manifests / lockfiles / build config present.
    manifest_fingerprint: Mapped[str | None] = mapped_column(String(64))
    #: Digest of a build artifact the SBOM was generated from, when one exists.
    #: Directory scans have no artifact; the column stays NULL rather than
    #: reusing the document checksum.
    artifact_digest: Mapped[str | None] = mapped_column(String(128))
    creation_reason: Mapped[str] = mapped_column(
        String(32), nullable=False, default=SbomSnapshotReason.FULL_SCAN.value
    )
    generation_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=SbomGenerationStatus.READY.value
    )
    previous_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("sboms.id", ondelete="SET NULL")
    )
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: NULL when the generator emitted no dependency graph (never guessed).
    direct_package_count: Mapped[int | None] = mapped_column(Integer)
    transitive_package_count: Mapped[int | None] = mapped_column(Integer)

    packages: Mapped[list[SbomPackage]] = relationship(
        back_populates="sbom", cascade="all, delete-orphan", passive_deletes=True
    )
    previous_snapshot: Mapped[Sbom | None] = relationship(remote_side="Sbom.id")

    __table_args__ = (
        Index("ix_sboms_asset_created", "asset_id", "created_at"),
        Index("ix_sboms_scan", "scan_id"),
        Index("ix_sboms_asset_dependency_fingerprint", "asset_id", "dependency_fingerprint"),
        Index("ix_sboms_asset_commit", "asset_id", "commit_sha"),
        # A lifecycle-generated snapshot is unique per (repository, composition,
        # commit), so a re-run generation job cannot create a duplicate row. Full
        # scans are excluded: every scan owns its own artifact even when the
        # composition is unchanged (that is what makes scan history auditable).
        Index(
            "uq_sboms_asset_fingerprint_commit",
            "asset_id",
            "dependency_fingerprint",
            "commit_sha",
            unique=True,
            postgresql_where=text(
                "dependency_fingerprint IS NOT NULL AND commit_sha IS NOT NULL "
                "AND creation_reason <> 'FULL_SCAN'"
            ),
        ),
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
    #: True when the package is declared by a manifest in the repository rather
    #: than pulled in by another package. NULL when the generator did not say.
    is_direct: Mapped[bool | None] = mapped_column(Boolean)

    sbom: Mapped[Sbom] = relationship(back_populates="packages")

    __table_args__ = (
        Index("ix_sbom_packages_sbom", "sbom_id"),
        Index("ix_sbom_packages_name_version", "name", "version"),
        Index("ix_sbom_packages_ecosystem_name", "ecosystem", "name"),
        # Reassessment matches stored intel on (ecosystem, name) and refreshes
        # findings by (name, version); a covering index keeps both paths cheap.
        Index("ix_sbom_packages_sbom_name_version", "sbom_id", "name", "version"),
    )


class SbomPackageEdge(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A dependency relationship extracted from the SBOM document.

    CycloneDX ``dependencies`` is a graph; the package table is a list. Without
    these rows the platform cannot answer "is this direct or transitive" or
    "what pulls this package in", which is the difference between a CVSS guess
    and a contextual risk.
    """

    __tablename__ = "sbom_package_edges"

    sbom_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False
    )
    #: ``from_ref`` is the CycloneDX bom-ref of the dependent package; NULL for a
    #: root (the scanned subject) whose children are direct dependencies.
    from_ref: Mapped[str | None] = mapped_column(String(500))
    to_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    from_name: Mapped[str | None] = mapped_column(String(255))
    from_version: Mapped[str | None] = mapped_column(String(128))
    to_name: Mapped[str | None] = mapped_column(String(255))
    to_version: Mapped[str | None] = mapped_column(String(128))
    relation: Mapped[str] = mapped_column(String(32), nullable=False, default="DEPENDS_ON")

    __table_args__ = (
        Index("ix_sbom_edges_sbom", "sbom_id"),
        Index("ix_sbom_edges_to_name", "sbom_id", "to_name"),
        Index("ix_sbom_edges_from_name", "sbom_id", "from_name"),
    )


class SbomMonitoringRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One execution of a continuous SBOM operation.

    Three operations share this table because they form one timeline per
    repository and all need the same counters/durations:

    * ``DEPENDENCY_CHECK`` — lightweight metadata comparison (no clone);
    * ``SBOM_GENERATION`` — checkout + Syft, new immutable snapshot;
    * ``VULNERABILITY_REASSESSMENT`` — stored inventory vs stored intel.

    ``metrics`` holds operation-specific facts (changed paths, component diff
    counts, intel sync id). Only counts that were actually observed are stored.
    """

    __tablename__ = "sbom_monitoring_runs"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    #: Snapshot the run generated (SBOM_GENERATION) or evaluated (reassessment).
    sbom_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("sboms.id", ondelete="SET NULL")
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    trigger: Mapped[str] = mapped_column(String(32), nullable=False, default="SCHEDULED")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="RUNNING")
    #: ``DependencyChangeOutcome`` for dependency checks; NULL otherwise.
    outcome: Mapped[str | None] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    head_commit_sha: Mapped[str | None] = mapped_column(String(64))
    previous_commit_sha: Mapped[str | None] = mapped_column(String(64))
    branch: Mapped[str | None] = mapped_column(String(200))
    dependency_fingerprint: Mapped[str | None] = mapped_column(String(64))
    previous_dependency_fingerprint: Mapped[str | None] = mapped_column(String(64))

    components_evaluated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_kev_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    skipped_reason: Mapped[str | None] = mapped_column(String(255))
    error_message: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        CheckConstraint(
            "kind IN ('DEPENDENCY_CHECK','SBOM_GENERATION','VULNERABILITY_REASSESSMENT')",
            name="sbom_monitoring_kind",
        ),
        CheckConstraint(
            "status IN ('RUNNING','SUCCEEDED','PARTIAL','FAILED','SKIPPED')",
            name="sbom_monitoring_status",
        ),
        Index("ix_sbom_monitoring_asset_kind_started", "asset_id", "kind", "started_at"),
        Index("ix_sbom_monitoring_kind_started", "kind", "started_at"),
        Index("ix_sbom_monitoring_status", "status"),
        Index("ix_sbom_monitoring_sbom", "sbom_id"),
    )
