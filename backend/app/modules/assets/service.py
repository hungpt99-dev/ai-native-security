"""Asset inventory business logic.

Credentials are encrypted on write and only ever decrypted by the worker when
building the git clone URL; API responses carry a masked hint only.
"""

from __future__ import annotations

import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.core.security import decrypt_secret, encrypt_secret, mask_secret
from app.core.validators import validate_repository_url
from app.modules.assets.models import Asset, AssetCredential
from app.modules.assets.repository import asset_query, get_asset, get_asset_by_url
from app.modules.assets.schemas import AssetCreate, AssetUpdate

logger = get_logger(__name__)


def list_assets(
    db: Session,
    params: PageParams,
    *,
    search: str | None = None,
    provider: str | None = None,
    monitoring_enabled: bool | None = None,
    sort_by: str | None = None,
    sort_order: str = "desc",
) -> tuple[list[Asset], int]:
    stmt = asset_query(search=search, provider=provider, monitoring_enabled=monitoring_enabled)
    sort_columns = {
        "name": Asset.name,
        "repo_url": Asset.repo_url,
        "created_at": Asset.created_at,
        "updated_at": Asset.updated_at,
        "last_scan_at": Asset.last_scan_at,
    }
    column = sort_columns.get(sort_by or "", Asset.created_at)
    stmt = stmt.order_by(column.asc() if sort_order.lower() == "asc" else column.desc())
    return paginate(db, stmt, params)


def get_asset_or_404(db: Session, asset_id: uuid.UUID) -> Asset:
    asset = get_asset(db, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found", details={"asset_id": str(asset_id)})
    return asset


def create_asset(db: Session, payload: AssetCreate) -> Asset:
    reference = validate_repository_url(payload.repo_url)
    if get_asset_by_url(db, reference.url):
        raise ConflictError(
            "Repository is already registered", details={"repo_url": reference.url}
        )

    asset = Asset(
        name=payload.name,
        repo_url=reference.url,
        provider=reference.provider.upper(),
        default_branch=payload.default_branch,
        description=payload.description,
        monitoring_enabled=payload.monitoring_enabled,
        scan_interval_minutes=payload.scan_interval_minutes,
    )
    if payload.access_token:
        asset.credential = _build_credential(reference.provider.upper(), payload.access_token)

    db.add(asset)
    try:
        db.flush()
    except IntegrityError as exc:  # race on the unique repo_url constraint
        db.rollback()
        raise ConflictError("Repository is already registered") from exc
    logger.info(
        "asset created",
        extra={"extra_fields": {"asset_id": str(asset.id), "provider": asset.provider}},
    )
    return asset


def update_asset(db: Session, asset: Asset, payload: AssetUpdate) -> Asset:
    data = payload.model_dump(exclude_unset=True)

    if "name" in data and data["name"]:
        asset.name = data["name"]
    if "default_branch" in data and data["default_branch"]:
        asset.default_branch = data["default_branch"]
    if "description" in data:
        asset.description = data["description"]
    if "monitoring_enabled" in data and data["monitoring_enabled"] is not None:
        asset.monitoring_enabled = bool(data["monitoring_enabled"])
    if "scan_interval_minutes" in data:
        asset.scan_interval_minutes = data["scan_interval_minutes"]

    if data.get("clear_credential") and asset.credential_id:
        credential = asset.credential
        asset.credential_id = None
        asset.credential = None
        if credential is not None:
            db.delete(credential)

    token = data.get("access_token")
    if token:
        if asset.credential_id and asset.credential is not None:
            asset.credential.encrypted_secret = encrypt_secret(token)
            asset.credential.secret_hint = mask_secret(token)
        else:
            asset.credential = _build_credential(asset.provider, token)

    db.flush()
    return asset


def delete_asset(db: Session, asset: Asset) -> None:
    credential = asset.credential
    db.delete(asset)
    db.flush()
    if credential is not None:
        db.delete(credential)
        db.flush()


def resolve_access_token(db: Session, asset: Asset) -> str | None:
    """Decrypt the access token for a clone. Only the worker calls this."""
    if not asset.credential_id:
        return None
    credential = asset.credential
    if credential is None:
        raise ValidationError("Asset credential reference is invalid")
    return decrypt_secret(credential.encrypted_secret)


def _build_credential(provider: str, token: str) -> AssetCredential:
    cleaned = token.strip()
    if len(cleaned) < 8:
        raise ValidationError("Access token is too short")
    if any(ch in cleaned for ch in "\r\n\x00"):
        raise ValidationError("Access token contains invalid characters")
    return AssetCredential(
        label=f"{provider.lower()}-token",
        provider=provider,
        encrypted_secret=encrypt_secret(cleaned),
        secret_hint=mask_secret(cleaned),
    )
