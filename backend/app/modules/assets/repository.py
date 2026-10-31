"""Asset persistence queries."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.modules.assets.models import Asset, AssetCredential


def asset_query(
    *,
    search: str | None = None,
    provider: str | None = None,
    monitoring_enabled: bool | None = None,
) -> Select:
    stmt = select(Asset)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Asset.name.ilike(pattern), Asset.repo_url.ilike(pattern)))
    if provider:
        stmt = stmt.where(Asset.provider == provider.upper())
    if monitoring_enabled is not None:
        stmt = stmt.where(Asset.monitoring_enabled.is_(monitoring_enabled))
    return stmt


def get_asset(db: Session, asset_id: uuid.UUID) -> Asset | None:
    return db.get(Asset, asset_id)


def get_asset_by_url(db: Session, repo_url: str) -> Asset | None:
    return db.execute(select(Asset).where(Asset.repo_url == repo_url)).scalar_one_or_none()


def list_monitored_assets(db: Session) -> Sequence[Asset]:
    return db.execute(select(Asset).where(Asset.monitoring_enabled.is_(True))).scalars().all()


def get_credential(db: Session, credential_id: uuid.UUID) -> AssetCredential | None:
    return db.get(AssetCredential, credential_id)


def count_assets(db: Session) -> int:
    return int(db.execute(select(func.count(Asset.id))).scalar_one())
