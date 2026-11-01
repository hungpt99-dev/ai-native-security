"""Inbound repository webhook delivery log.

One row per delivery attempt, unique per ``(provider, delivery_id)``. The unique
constraint is the idempotency guard: a retried delivery from GitHub/GitLab can
never enqueue a second change check.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class WebhookDelivery(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "webhook_deliveries"

    provider: Mapped[str] = mapped_column(String(24), nullable=False)
    #: Provider delivery identifier (``X-GitHub-Delivery`` / ``X-Gitlab-Event-UUID``).
    delivery_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    repo_url: Mapped[str | None] = mapped_column(String(500))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL")
    )
    #: ENQUEUED | IGNORED | DUPLICATE | REJECTED | UNKNOWN_REPOSITORY
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(500))
    head_commit_sha: Mapped[str | None] = mapped_column(String(64))
    branch: Mapped[str | None] = mapped_column(String(200))
    changed_paths: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    payload_digest: Mapped[str | None] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: Raw provider headers minus signature/token values (never stores secrets).
    headers: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("provider", "delivery_id", name="uq_webhook_delivery"),
        CheckConstraint(
            "action IN ('ENQUEUED','IGNORED','DUPLICATE','REJECTED','UNKNOWN_REPOSITORY')",
            name="webhook_delivery_action",
        ),
        Index("ix_webhook_deliveries_received", "received_at"),
        Index("ix_webhook_deliveries_asset", "asset_id", "received_at"),
    )
