"""continuous SBOM lifecycle: snapshots, monitoring runs, webhook deliveries

Additive changes only. No existing column is renamed, dropped or retyped, so
the scan path, the SBOM endpoints and the finding lifecycle keep working.

Added:
* ``sboms`` provenance: commit, branch, dependency/manifest fingerprints,
  artifact digest, creation reason, generation status, lineage, generated_at and
  direct/transitive counts.
* ``sbom_monitoring_runs``: one row per dependency check, snapshot generation and
  vulnerability reassessment.
* ``webhook_deliveries``: idempotent record of provider deliveries.
* ``findings.discovery_source``: FULL_SCAN vs SBOM_REASSESSMENT provenance.
* Indexes for the new query paths, plus a partial unique index that makes an
  identical (asset, dependency fingerprint, commit) snapshot impossible.

Existing rows are backfilled with server defaults rather than left NULL where
the column is non-nullable. Backfilling fingerprints is deliberately not
attempted: they are derived from the inventory and cannot be invented in SQL, so
pre-existing snapshots keep NULL and are treated as "unknown composition
identity" until a new snapshot is generated.

Revision ID: 2cf7e16e149a
Revises: 0003_schedule_job_kinds
Create Date: 2026-11-01 07:51:53.348464
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "2cf7e16e149a"
down_revision: str | None = "0003_schedule_job_kinds"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_SCHEDULE_KINDS = (
    "('SCAN','SYNC_OSV','SYNC_NVD','SYNC_KEV','SYNC_EPSS',"
    "'AI_RISK','AI_INVESTIGATE','AI_REMEDIATE','AI_VERIFY')"
)
_NEW_SCHEDULE_KINDS = (
    "('SCAN','SYNC_OSV','SYNC_NVD','SYNC_KEV','SYNC_EPSS',"
    "'AI_RISK','AI_INVESTIGATE','AI_REMEDIATE','AI_VERIFY',"
    "'SBOM_CHANGE_CHECK','SBOM_GENERATE','SBOM_VULNERABILITY_REASSESSMENT')"
)
SCHEDULE_CONSTRAINT = "schedule_kind"


def upgrade() -> None:
    # ---------------------------------------------------------------- tables
    op.create_table(
        "webhook_deliveries",
        sa.Column("provider", sa.String(length=24), nullable=False),
        sa.Column("delivery_id", sa.String(length=128), nullable=False),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column("repo_url", sa.String(length=500), nullable=True),
        sa.Column("asset_id", sa.UUID(), nullable=True),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("head_commit_sha", sa.String(length=64), nullable=True),
        sa.Column("branch", sa.String(length=200), nullable=True),
        sa.Column(
            "changed_paths", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("payload_digest", sa.String(length=64), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("headers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ('ENQUEUED','IGNORED','DUPLICATE','REJECTED','UNKNOWN_REPOSITORY')",
            name=op.f("ck_webhook_deliveries_webhook_delivery_action"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_webhook_deliveries_asset_id_assets"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name=op.f("fk_webhook_deliveries_job_id_jobs"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_webhook_deliveries")),
        sa.UniqueConstraint("provider", "delivery_id", name="uq_webhook_delivery"),
    )
    op.create_index(
        "ix_webhook_deliveries_asset",
        "webhook_deliveries",
        ["asset_id", "received_at"],
        unique=False,
    )
    op.create_index(
        "ix_webhook_deliveries_received",
        "webhook_deliveries",
        ["received_at"],
        unique=False,
    )

    op.create_table(
        "sbom_monitoring_runs",
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("sbom_id", sa.UUID(), nullable=True),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("head_commit_sha", sa.String(length=64), nullable=True),
        sa.Column("previous_commit_sha", sa.String(length=64), nullable=True),
        sa.Column("branch", sa.String(length=200), nullable=True),
        sa.Column("dependency_fingerprint", sa.String(length=64), nullable=True),
        sa.Column(
            "previous_dependency_fingerprint", sa.String(length=64), nullable=True
        ),
        sa.Column("components_evaluated", sa.Integer(), nullable=False),
        sa.Column("findings_created", sa.Integer(), nullable=False),
        sa.Column("findings_updated", sa.Integer(), nullable=False),
        sa.Column("findings_resolved", sa.Integer(), nullable=False),
        sa.Column("new_kev_findings", sa.Integer(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("skipped_reason", sa.String(length=255), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "kind IN ('DEPENDENCY_CHECK','SBOM_GENERATION','VULNERABILITY_REASSESSMENT')",
            name=op.f("ck_sbom_monitoring_runs_sbom_monitoring_kind"),
        ),
        sa.CheckConstraint(
            "status IN ('RUNNING','SUCCEEDED','PARTIAL','FAILED','SKIPPED')",
            name=op.f("ck_sbom_monitoring_runs_sbom_monitoring_status"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_sbom_monitoring_runs_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name=op.f("fk_sbom_monitoring_runs_job_id_jobs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["sbom_id"],
            ["sboms.id"],
            name=op.f("fk_sbom_monitoring_runs_sbom_id_sboms"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sbom_monitoring_runs")),
    )
    op.create_index(
        "ix_sbom_monitoring_asset_kind_started",
        "sbom_monitoring_runs",
        ["asset_id", "kind", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_sbom_monitoring_kind_started",
        "sbom_monitoring_runs",
        ["kind", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_sbom_monitoring_sbom", "sbom_monitoring_runs", ["sbom_id"], unique=False
    )
    op.create_index(
        "ix_sbom_monitoring_status", "sbom_monitoring_runs", ["status"], unique=False
    )

    # --------------------------------------------------------------- findings
    op.add_column(
        "findings",
        sa.Column(
            "discovery_source",
            sa.String(length=32),
            server_default="FULL_SCAN",
            nullable=False,
        ),
    )
    op.create_index(
        "ix_findings_discovery_source", "findings", ["discovery_source"], unique=False
    )

    # ------------------------------------------------------------------ sboms
    op.add_column("sboms", sa.Column("commit_sha", sa.String(length=64), nullable=True))
    op.add_column("sboms", sa.Column("branch", sa.String(length=200), nullable=True))
    op.add_column(
        "sboms", sa.Column("dependency_fingerprint", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "sboms", sa.Column("manifest_fingerprint", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "sboms", sa.Column("artifact_digest", sa.String(length=128), nullable=True)
    )
    op.add_column(
        "sboms",
        sa.Column(
            "creation_reason",
            sa.String(length=32),
            server_default="FULL_SCAN",
            nullable=False,
        ),
    )
    op.add_column(
        "sboms",
        sa.Column(
            "generation_status",
            sa.String(length=16),
            server_default="READY",
            nullable=False,
        ),
    )
    op.add_column("sboms", sa.Column("previous_snapshot_id", sa.UUID(), nullable=True))
    op.add_column(
        "sboms", sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("sboms", sa.Column("direct_package_count", sa.Integer(), nullable=True))
    op.add_column(
        "sboms", sa.Column("transitive_package_count", sa.Integer(), nullable=True)
    )
    # Existing snapshots predate explicit generation bookkeeping: the row's own
    # timestamp is the only truthful generation time we can state.
    op.execute("UPDATE sboms SET generated_at = created_at WHERE generated_at IS NULL")
    op.create_index("ix_sboms_asset_commit", "sboms", ["asset_id", "commit_sha"], unique=False)
    op.create_index(
        "ix_sboms_asset_dependency_fingerprint",
        "sboms",
        ["asset_id", "dependency_fingerprint"],
        unique=False,
    )
    op.create_index(
        "uq_sboms_asset_fingerprint_commit",
        "sboms",
        ["asset_id", "dependency_fingerprint", "commit_sha"],
        unique=True,
        postgresql_where=sa.text(
            "dependency_fingerprint IS NOT NULL AND commit_sha IS NOT NULL "
            "AND creation_reason <> 'FULL_SCAN'"
        ),
    )
    op.create_foreign_key(
        op.f("fk_sboms_previous_snapshot_id_sboms"),
        "sboms",
        "sboms",
        ["previous_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )
    # Reassessment joins inventory to findings by (name, version) inside one
    # snapshot; this covering index keeps the join off the seq-scan path.
    op.create_index(
        "ix_sbom_packages_sbom_name_version",
        "sbom_packages",
        ["sbom_id", "name", "version"],
        unique=False,
    )

    # ------------------------------------------------------------- schedules
    op.drop_constraint(SCHEDULE_CONSTRAINT, "schedules", type_="check")
    op.create_check_constraint(
        SCHEDULE_CONSTRAINT, "schedules", f"kind IN {_NEW_SCHEDULE_KINDS}"
    )


def downgrade() -> None:
    # Schedules referencing the new job kinds cannot survive the constraint
    # change; remove them explicitly instead of failing the downgrade.
    op.execute(
        "DELETE FROM schedules WHERE kind IN "
        "('SBOM_CHANGE_CHECK','SBOM_GENERATE','SBOM_VULNERABILITY_REASSESSMENT')"
    )
    op.drop_constraint(SCHEDULE_CONSTRAINT, "schedules", type_="check")
    op.create_check_constraint(
        SCHEDULE_CONSTRAINT, "schedules", f"kind IN {_OLD_SCHEDULE_KINDS}"
    )

    op.drop_index("ix_sbom_packages_sbom_name_version", table_name="sbom_packages")
    op.drop_constraint(
        op.f("fk_sboms_previous_snapshot_id_sboms"), "sboms", type_="foreignkey"
    )
    op.drop_index(
        "uq_sboms_asset_fingerprint_commit",
        table_name="sboms",
        postgresql_where=sa.text(
            "dependency_fingerprint IS NOT NULL AND commit_sha IS NOT NULL "
            "AND creation_reason <> 'FULL_SCAN'"
        ),
    )
    op.drop_index("ix_sboms_asset_dependency_fingerprint", table_name="sboms")
    op.drop_index("ix_sboms_asset_commit", table_name="sboms")
    op.drop_column("sboms", "transitive_package_count")
    op.drop_column("sboms", "direct_package_count")
    op.drop_column("sboms", "generated_at")
    op.drop_column("sboms", "previous_snapshot_id")
    op.drop_column("sboms", "generation_status")
    op.drop_column("sboms", "creation_reason")
    op.drop_column("sboms", "artifact_digest")
    op.drop_column("sboms", "manifest_fingerprint")
    op.drop_column("sboms", "dependency_fingerprint")
    op.drop_column("sboms", "branch")
    op.drop_column("sboms", "commit_sha")

    op.drop_index("ix_findings_discovery_source", table_name="findings")
    op.drop_column("findings", "discovery_source")

    op.drop_index("ix_sbom_monitoring_status", table_name="sbom_monitoring_runs")
    op.drop_index("ix_sbom_monitoring_sbom", table_name="sbom_monitoring_runs")
    op.drop_index("ix_sbom_monitoring_kind_started", table_name="sbom_monitoring_runs")
    op.drop_index(
        "ix_sbom_monitoring_asset_kind_started", table_name="sbom_monitoring_runs"
    )
    op.drop_table("sbom_monitoring_runs")
    op.drop_index("ix_webhook_deliveries_received", table_name="webhook_deliveries")
    op.drop_index("ix_webhook_deliveries_asset", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
