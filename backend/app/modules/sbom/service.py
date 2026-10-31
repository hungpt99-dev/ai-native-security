"""SBOM persistence: store documents behind the storage abstraction."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.core.storage import StorageBackend, get_storage
from app.modules.sbom.models import Sbom, SbomPackage
from app.modules.scanners.syft import SbomDocument

logger = get_logger(__name__)


def store_sbom(
    db: Session,
    *,
    asset_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    document: SbomDocument,
    storage: StorageBackend | None = None,
) -> Sbom:
    storage = storage or get_storage()
    stamp = datetime.now(UTC).strftime("%Y/%m/%d")
    key = f"sboms/{asset_id}/{stamp}/{uuid.uuid4()}.json"
    storage.put(key, document.content)

    sbom = Sbom(
        asset_id=asset_id,
        scan_id=scan_id,
        format=document.format,
        spec_version=document.spec_version,
        tool_name="syft",
        tool_version=document.tool_version,
        storage_key=key,
        sha256=storage.checksum(document.content),
        size_bytes=len(document.content),
        package_count=len(document.packages),
        source_type="filesystem",
    )
    db.add(sbom)
    db.flush()

    seen: set[tuple[str, str, str | None]] = set()
    for package in document.packages:
        marker = (package.name.lower(), package.version, package.purl)
        if marker in seen:
            continue
        seen.add(marker)
        db.add(
            SbomPackage(
                sbom_id=sbom.id,
                name=package.name,
                version=package.version,
                ecosystem=package.ecosystem,
                purl=package.purl,
                license=package.license,
                source_type=package.source_type,
                cpe=package.cpe,
            )
        )
    db.flush()
    logger.info(
        "sbom stored",
        extra={
            "extra_fields": {
                "sbom_id": str(sbom.id),
                "asset_id": str(asset_id),
                "packages": sbom.package_count,
                "bytes": sbom.size_bytes,
            }
        },
    )
    return sbom


def list_sboms(
    db: Session, params: PageParams, *, asset_id: uuid.UUID | None = None
) -> tuple[list[Sbom], int]:
    stmt: Select = select(Sbom)
    if asset_id:
        stmt = stmt.where(Sbom.asset_id == asset_id)
    stmt = stmt.order_by(Sbom.created_at.desc())
    return paginate(db, stmt, params)


def get_sbom_or_404(db: Session, sbom_id: uuid.UUID) -> Sbom:
    sbom = db.get(Sbom, sbom_id)
    if sbom is None:
        raise NotFoundError("SBOM not found", details={"sbom_id": str(sbom_id)})
    return sbom


def list_packages(
    db: Session,
    sbom_id: uuid.UUID,
    params: PageParams,
    *,
    search: str | None = None,
    ecosystem: str | None = None,
) -> tuple[list[SbomPackage], int]:
    stmt: Select = select(SbomPackage).where(SbomPackage.sbom_id == sbom_id)
    if search:
        stmt = stmt.where(SbomPackage.name.ilike(f"%{search.strip()}%"))
    if ecosystem:
        stmt = stmt.where(SbomPackage.ecosystem == ecosystem)
    stmt = stmt.order_by(SbomPackage.name.asc(), SbomPackage.version.asc())
    return paginate(db, stmt, params)


def download_sbom(
    db: Session, sbom_id: uuid.UUID, storage: StorageBackend | None = None
) -> tuple[bytes, str, str]:
    sbom = get_sbom_or_404(db, sbom_id)
    storage = storage or get_storage()
    content = storage.get(sbom.storage_key)
    filename = f"sbom-{sbom.id}.json"
    media_type = "application/json"
    return content, filename, media_type


def latest_sbom_for_asset(db: Session, asset_id: uuid.UUID) -> Sbom | None:
    return db.execute(
        select(Sbom)
        .where(Sbom.asset_id == asset_id)
        .order_by(Sbom.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
