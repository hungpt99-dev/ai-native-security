"""Versioned security policies.

Policy is data, not code: the scoring weights, the AI/deterministic blend and the
severity gates live in a JSON document so a change is reviewable, testable and
attributable to a version that every risk assessment records.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Boolean, CheckConstraint, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import POLICY_KINDS
from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

_POLICY_KIND_SQL = ",".join(f"'{kind}'" for kind in POLICY_KINDS)


class SecurityPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "security_policies"

    key: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    __table_args__ = (
        UniqueConstraint("key", "version", name="uq_security_policies_key_version"),
        CheckConstraint(f"kind IN ({_POLICY_KIND_SQL})", name="security_policy_kind"),
        Index("ix_security_policies_kind_active", "kind", "active"),
    )
