"""unified security domains: events, incidents, infrastructure, threat intel, audit

Additive migration. It extends the existing asset inventory with a ``kind`` and
an external identity so container images, hosts and cloud resources live next to
repositories instead of in a fork of the inventory, then adds the platform
tables that consume them.

No existing column is renamed or retyped; ``assets.repo_url`` becomes nullable
only so non-repository assets can exist (PostgreSQL unique constraints ignore
NULLs, so repository uniqueness is unchanged).

Revision ID: 4a1b2c3d4e5f
Revises: 2cf7e16e149a
Create Date: 2026-11-07 07:05:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "4a1b2c3d4e5f"
down_revision: str | None = "2cf7e16e149a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ------------------------------------------------------- job kind catalogue
    # Two new job kinds must be schedulable. The constraint is rebuilt from the
    # same list the ORM derives, so the database and the enum cannot drift.
    op.drop_constraint("schedule_kind", "schedules", type_="check")
    op.create_check_constraint(
        "schedule_kind",
        "schedules",
        "kind IN ('SCAN','SYNC_OSV','SYNC_NVD','SYNC_KEV','SYNC_EPSS','AI_RISK',"
        "'AI_INVESTIGATE','AI_REMEDIATE','AI_VERIFY','SBOM_CHANGE_CHECK','SBOM_GENERATE',"
        "'SBOM_VULNERABILITY_REASSESSMENT','INFRA_SCAN','RUNTIME_ANOMALY_SCAN')",
    )

    # ------------------------------------------------------------ asset kinds
    op.add_column(
        "assets",
        sa.Column("kind", sa.String(length=32), nullable=False, server_default="REPOSITORY"),
    )
    op.add_column("assets", sa.Column("external_ref", sa.String(length=500), nullable=True))
    op.add_column("assets", sa.Column("parent_asset_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("assets", sa.Column("infra_scan_interval_minutes", sa.Integer(), nullable=True))
    op.add_column("assets", sa.Column("last_infra_scan_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assets", sa.Column("last_infra_scan_status", sa.String(length=16), nullable=True))
    op.alter_column("assets", "repo_url", existing_type=sa.String(length=500), nullable=True)
    op.create_foreign_key(
        "fk_assets_parent_asset_id_assets",
        "assets",
        "assets",
        ["parent_asset_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_assets_kind", "assets", ["kind"])
    op.create_index("ix_assets_parent", "assets", ["parent_asset_id"])
    op.create_index(
        "uq_assets_kind_external_ref",
        "assets",
        ["kind", "external_ref"],
        unique=True,
        postgresql_where=sa.text("external_ref IS NOT NULL"),
    )

    # --------------------------------------------------------------- incidents
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="MEDIUM"),
        sa.Column("priority", sa.String(length=4), nullable=False, server_default="P3"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="OPEN"),
        sa.Column("category", sa.String(length=24), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("correlation_key", sa.String(length=250), nullable=False),
        sa.Column("detection_rule_slug", sa.String(length=120), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assigned_to", sa.String(length=120), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.CheckConstraint(
            "status IN ('OPEN','TRIAGING','INVESTIGATING','CONTAINED','RESOLVED','CLOSED')",
            name="incident_status",
        ),
        sa.CheckConstraint("priority IN ('P1','P2','P3','P4')", name="incident_priority"),
        sa.CheckConstraint(
            "severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN')",
            name="incident_severity",
        ),
        sa.CheckConstraint(
            "category IS NULL OR category IN "
            "('RUNTIME','NETWORK','IDENTITY','INFRASTRUCTURE','APPLICATION','DATA')",
            name="incident_category",
        ),
    )
    op.create_index("ix_incidents_status_opened", "incidents", ["status", "opened_at"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_asset", "incidents", ["asset_id", "opened_at"])
    op.create_index("ix_incidents_correlation", "incidents", ["correlation_key", "status"])
    op.create_index("ix_incidents_opened", "incidents", ["opened_at"])

    # ----------------------------------------------------------- detection rules
    op.create_table(
        "detection_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(length=120), nullable=False, unique=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=24), nullable=False, server_default="RUNTIME"),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="MEDIUM"),
        sa.Column("rule_type", sa.String(length=16), nullable=False, server_default="SIGNATURE"),
        sa.Column("source", sa.String(length=16), nullable=False, server_default="BUILTIN"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("conditions", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("threshold", postgresql.JSONB(), nullable=True),
        sa.Column("create_incident", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("incident_priority", sa.String(length=4), nullable=True),
        sa.Column("last_matched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("match_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(length=120), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "category IN ('RUNTIME','NETWORK','IDENTITY','INFRASTRUCTURE','APPLICATION','DATA')",
            name="detection_rule_category",
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN')",
            name="detection_rule_severity",
        ),
        sa.CheckConstraint(
            "rule_type IN ('SIGNATURE','THRESHOLD','ANOMALY')", name="detection_rule_type"
        ),
        sa.CheckConstraint("source IN ('BUILTIN','CUSTOM')", name="detection_rule_source"),
        sa.CheckConstraint(
            "incident_priority IS NULL OR incident_priority IN ('P1','P2','P3','P4')",
            name="detection_rule_priority",
        ),
    )
    op.create_index("ix_detection_rules_enabled", "detection_rules", ["enabled"])
    op.create_index("ix_detection_rules_category", "detection_rules", ["category"])

    # ---------------------------------------------------------- security events
    op.create_table(
        "security_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False, unique=True),
        sa.Column("category", sa.String(length=24), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="GENERIC"),
        sa.Column("source_event_id", sa.String(length=200), nullable=True),
        sa.Column("event_type", sa.String(length=160), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="OPEN"),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("detection_rule_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rule_slug", sa.String(length=120), nullable=True),
        sa.Column("rule_version", sa.Integer(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("normalized", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("indicators", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("enrichment", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["detection_rule_id"], ["detection_rules.id"], ondelete="SET NULL"),
        sa.CheckConstraint(
            "category IN ('RUNTIME','NETWORK','IDENTITY','INFRASTRUCTURE','APPLICATION','DATA')",
            name="security_event_category",
        ),
        sa.CheckConstraint(
            "source IN ('FALCO','KUBERNETES_AUDIT','NETWORK_SENSOR','IDENTITY_PROVIDER',"
            "'APPLICATION_LOG','GENERIC')",
            name="security_event_source",
        ),
        sa.CheckConstraint("status IN ('OPEN','ACKNOWLEDGED','CLOSED')", name="security_event_status"),
        sa.CheckConstraint(
            "severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN')",
            name="security_event_severity",
        ),
    )
    op.create_index("ix_security_events_last_seen", "security_events", ["last_seen_at"])
    op.create_index(
        "ix_security_events_category_seen", "security_events", ["category", "last_seen_at"]
    )
    op.create_index(
        "ix_security_events_asset_seen", "security_events", ["asset_id", "last_seen_at"]
    )
    op.create_index("ix_security_events_incident", "security_events", ["incident_id"])
    op.create_index(
        "ix_security_events_status_seen", "security_events", ["status", "last_seen_at"]
    )
    op.create_index("ix_security_events_severity", "security_events", ["severity"])
    op.create_index("ix_security_events_source", "security_events", ["source"])
    op.create_index("ix_security_events_rule", "security_events", ["rule_slug"])
    op.create_index(
        "uq_security_events_source_event_id",
        "security_events",
        ["source", "source_event_id"],
        unique=True,
        postgresql_where=sa.text("source_event_id IS NOT NULL"),
    )

    op.create_table(
        "security_event_notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author", sa.String(length=120), nullable=False, server_default="system"),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["event_id"], ["security_events.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_security_event_notes_event", "security_event_notes", ["event_id", "created_at"]
    )

    # ------------------------------------------------------------ incident links
    op.create_table(
        "incident_timeline",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=False, server_default="system"),
        sa.Column("detail", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "kind IN ('CREATED','EVENT_ATTACHED','FINDING_ATTACHED','STATUS_CHANGED',"
            "'ASSIGNED','NOTE','AI_INVESTIGATION','REMEDIATION','CORRELATION')",
            name="incident_timeline_kind",
        ),
    )
    op.create_index(
        "ix_incident_timeline_incident_created", "incident_timeline", ["incident_id", "created_at"]
    )

    op.create_table(
        "incident_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reason", sa.String(length=120), nullable=False, server_default="manual"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("incident_id", "finding_id", name="uq_incident_findings_pair"),
    )
    op.create_index("ix_incident_findings_finding", "incident_findings", ["finding_id"])

    op.create_table(
        "incident_investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("missing_information", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("next_actions", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("attack_steps", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("ai_execution_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("model", sa.String(length=96), nullable=False, server_default=""),
        sa.Column("prompt_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("prompt_version", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_execution_id"], ["ai_executions.id"], ondelete="SET NULL"),
    )
    op.create_index(
        "ix_incident_investigations_incident_created",
        "incident_investigations",
        ["incident_id", "created_at"],
    )

    # ----------------------------------------------------------- infrastructure
    op.create_table(
        "infrastructure_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("target_ref", sa.String(length=500), nullable=False),
        sa.Column("scanner", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="PENDING"),
        sa.Column("triggered_by", sa.String(length=32), nullable=False, server_default="MANUAL"),
        sa.Column("requested_by", sa.String(length=120), nullable=True),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("scanner_version", sa.String(length=64), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "status IN ('PENDING','RUNNING','COMPLETED','FAILED','SKIPPED')",
            name="infrastructure_scan_status",
        ),
        sa.CheckConstraint(
            "target_kind IN ('IAC_REPOSITORY','CONTAINER_IMAGE','KUBERNETES_MANIFEST','CLOUD_CONFIG')",
            name="infrastructure_scan_target",
        ),
        sa.CheckConstraint(
            "scanner IN ('trivy-config','checkov','trivy-image')",
            name="infrastructure_scan_scanner",
        ),
    )
    op.create_index(
        "ix_infrastructure_scans_asset_created", "infrastructure_scans", ["asset_id", "created_at"]
    )
    op.create_index("ix_infrastructure_scans_status", "infrastructure_scans", ["status"])
    op.create_index(
        "ix_infrastructure_scans_target", "infrastructure_scans", ["target_kind", "target_ref"]
    )
    op.create_index(
        "uq_infrastructure_scans_active_target",
        "infrastructure_scans",
        ["target_kind", "target_ref", "scanner"],
        unique=True,
        postgresql_where=sa.text("status IN ('PENDING','RUNNING')"),
    )

    # ------------------------------------------------------------ threat intel
    op.create_table(
        "threat_indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="MANUAL"),
        sa.Column("source_ref", sa.String(length=200), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="HIGH"),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tags", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "indicator_type IN ('IP','DOMAIN','URL','SHA256','MD5','EMAIL')",
            name="threat_indicator_type",
        ),
        sa.CheckConstraint(
            "source IN ('MANUAL','CSV_IMPORT','EXTERNAL_FEED','INTERNAL')",
            name="threat_indicator_source",
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN')",
            name="threat_indicator_severity",
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 100", name="threat_indicator_confidence"),
        sa.UniqueConstraint(
            "indicator_type", "value", "source", name="uq_threat_indicators_identity"
        ),
    )
    op.create_index(
        "ix_threat_indicators_type_value", "threat_indicators", ["indicator_type", "value"]
    )
    op.create_index("ix_threat_indicators_active", "threat_indicators", ["active", "expires_at"])
    op.create_index(
        "ix_threat_indicators_source_ingested", "threat_indicators", ["source", "ingested_at"]
    )

    op.create_table(
        "threat_intel_ingests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=False, server_default="system"),
        sa.Column("received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_threat_intel_ingests_created", "threat_intel_ingests", ["created_at"])

    # ------------------------------------------------------------------- audit
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("actor", sa.String(length=120), nullable=False, server_default="anonymous"),
        sa.Column("action", sa.String(length=24), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=120), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_audit_log_created", "audit_log", ["created_at"])
    op.create_index("ix_audit_log_actor_created", "audit_log", ["actor", "created_at"])
    op.create_index("ix_audit_log_resource", "audit_log", ["resource_type", "resource_id"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_resource", table_name="audit_log")
    op.drop_index("ix_audit_log_actor_created", table_name="audit_log")
    op.drop_index("ix_audit_log_created", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_index("ix_threat_intel_ingests_created", table_name="threat_intel_ingests")
    op.drop_table("threat_intel_ingests")
    op.drop_index("ix_threat_indicators_source_ingested", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_active", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_type_value", table_name="threat_indicators")
    op.drop_table("threat_indicators")

    op.drop_index("uq_infrastructure_scans_active_target", table_name="infrastructure_scans")
    op.drop_index("ix_infrastructure_scans_target", table_name="infrastructure_scans")
    op.drop_index("ix_infrastructure_scans_status", table_name="infrastructure_scans")
    op.drop_index("ix_infrastructure_scans_asset_created", table_name="infrastructure_scans")
    op.drop_table("infrastructure_scans")

    op.drop_index(
        "ix_incident_investigations_incident_created", table_name="incident_investigations"
    )
    op.drop_table("incident_investigations")
    op.drop_index("ix_incident_findings_finding", table_name="incident_findings")
    op.drop_table("incident_findings")
    op.drop_index("ix_incident_timeline_incident_created", table_name="incident_timeline")
    op.drop_table("incident_timeline")

    op.drop_index("ix_security_event_notes_event", table_name="security_event_notes")
    op.drop_table("security_event_notes")
    op.drop_index("uq_security_events_source_event_id", table_name="security_events")
    op.drop_index("ix_security_events_rule", table_name="security_events")
    op.drop_index("ix_security_events_source", table_name="security_events")
    op.drop_index("ix_security_events_severity", table_name="security_events")
    op.drop_index("ix_security_events_status_seen", table_name="security_events")
    op.drop_index("ix_security_events_incident", table_name="security_events")
    op.drop_index("ix_security_events_asset_seen", table_name="security_events")
    op.drop_index("ix_security_events_category_seen", table_name="security_events")
    op.drop_index("ix_security_events_last_seen", table_name="security_events")
    op.drop_table("security_events")

    op.drop_index("ix_detection_rules_category", table_name="detection_rules")
    op.drop_index("ix_detection_rules_enabled", table_name="detection_rules")
    op.drop_table("detection_rules")

    op.drop_index("ix_incidents_opened", table_name="incidents")
    op.drop_index("ix_incidents_correlation", table_name="incidents")
    op.drop_index("ix_incidents_asset", table_name="incidents")
    op.drop_index("ix_incidents_severity", table_name="incidents")
    op.drop_index("ix_incidents_status_opened", table_name="incidents")
    op.drop_table("incidents")

    op.drop_index("uq_assets_kind_external_ref", table_name="assets")
    op.drop_index("ix_assets_parent", table_name="assets")
    op.drop_index("ix_assets_kind", table_name="assets")
    op.drop_constraint("fk_assets_parent_asset_id_assets", "assets", type_="foreignkey")
    op.alter_column("assets", "repo_url", existing_type=sa.String(length=500), nullable=False)
    op.drop_column("assets", "last_infra_scan_status")
    op.drop_column("assets", "last_infra_scan_at")
    op.drop_column("assets", "infra_scan_interval_minutes")
    op.drop_column("assets", "parent_asset_id")
    op.drop_column("assets", "external_ref")
    op.drop_column("assets", "kind")

    op.drop_constraint("schedule_kind", "schedules", type_="check")
    op.create_check_constraint(
        "schedule_kind",
        "schedules",
        "kind IN ('SCAN','SYNC_OSV','SYNC_NVD','SYNC_KEV','SYNC_EPSS','AI_RISK',"
        "'AI_INVESTIGATE','AI_REMEDIATE','AI_VERIFY','SBOM_CHANGE_CHECK','SBOM_GENERATE',"
        "'SBOM_VULNERABILITY_REASSESSMENT')",
    )
