"""SBOM storage and retrieval API."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.errors import ExternalServiceError
from app.core.storage import LocalFileStorage
from app.modules.sbom import service
from app.modules.sbom.models import Sbom
from app.modules.scanners.syft import (
    SbomDocument,
    SbomPackageInfo,
    SyftGenerator,
    normalize_sbom_format,
)


def _document() -> SbomDocument:
    return SbomDocument(
        content=b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"requests"}]}',
        format="CYCLONEDX_JSON",
        spec_version="1.5",
        tool_version="syft-1.33.0",
        packages=[
            SbomPackageInfo(
                name="requests",
                version="2.31.0",
                ecosystem="PyPI",
                purl="pkg:pypi/requests@2.31.0",
                license="Apache-2.0",
                source_type="python",
            ),
            SbomPackageInfo(
                name="lodash",
                version="4.17.21",
                ecosystem="npm",
                purl="pkg:npm/lodash@4.17.21",
                license="MIT",
                source_type="javascript",
            ),
        ],
    )


def test_sbom_endpoints(client: TestClient, db: Session, asset_factory, storage: LocalFileStorage) -> None:
    asset = asset_factory()
    sbom = service.store_sbom(db, asset_id=asset.id, scan_id=None, document=_document(), storage=storage)
    db.commit()

    listing = client.get(f"/api/v1/assets/{asset.id}/sboms")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1
    assert body["items"][0]["package_count"] == 2

    detail = client.get(f"/api/v1/sboms/{sbom.id}")
    assert detail.status_code == 200
    assert detail.json()["format"] == "CYCLONEDX_JSON"
    assert detail.json()["spec_version"] == "1.5"

    packages = client.get(f"/api/v1/sboms/{sbom.id}/packages", params={"page_size": 10}).json()
    assert packages["total"] == 2
    assert {item["name"] for item in packages["items"]} == {"requests", "lodash"}

    filtered = client.get(
        f"/api/v1/sboms/{sbom.id}/packages", params={"ecosystem": "npm"}
    ).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["name"] == "lodash"

    download = client.get(f"/api/v1/sboms/{sbom.id}/download")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/json")
    assert b"CycloneDX" in download.content


def test_sbom_document_is_not_stored_in_database(
    db: Session, asset_factory, storage: LocalFileStorage
) -> None:
    asset = asset_factory()
    sbom = service.store_sbom(db, asset_id=asset.id, scan_id=None, document=_document(), storage=storage)
    db.flush()
    assert sbom.storage_key.startswith(f"sboms/{asset.id}/")
    assert storage.exists(sbom.storage_key)
    assert len(sbom.sha256) == 64
    columns = set(Sbom.__table__.columns.keys())
    assert "content" not in columns and "document" not in columns


def test_unknown_sbom_returns_404(client: TestClient) -> None:
    response = client.get(f"/api/v1/sboms/{uuid.uuid4()}")
    assert response.status_code == 404


def test_tampered_storage_key_is_rejected(client: TestClient, db: Session, asset_factory) -> None:
    asset = asset_factory()
    document = _document()
    from app.core.storage import LocalFileStorage as _Storage

    class TraversalStorage(_Storage):
        def put(self, key: str, data: bytes) -> str:  # noqa: ARG002
            # Simulate a corrupted row pointing outside the storage root.
            return "../../etc/passwd"

    sbom = service.store_sbom(
        db, asset_id=asset.id, scan_id=None, document=document, storage=TraversalStorage("/tmp/ans-x")
    )
    db.commit()
    response = client.get(f"/api/v1/sboms/{sbom.id}/download")
    assert response.status_code in {422, 404}
    assert "root:" not in response.text


def test_syft_parses_cyclonedx() -> None:
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "flask",
                "version": "3.0.0",
                "purl": "pkg:pypi/flask@3.0.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            },
            {
                "type": "library",
                "name": "flask",
                "version": "3.0.0",
                "purl": "pkg:pypi/flask@3.0.0",
            },
        ],
    }
    packages, spec_version = SyftGenerator().parse_result(payload, "CYCLONEDX_JSON")
    assert spec_version == "1.6"
    assert len(packages) == 1  # duplicates collapse
    assert packages[0].ecosystem == "PyPI"
    assert packages[0].license == "BSD-3-Clause"


def test_syft_parses_spdx() -> None:
    payload = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "openssl",
                "versionInfo": "3.0.12",
                "licenseDeclared": "Apache-2.0",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:deb/debian/openssl@3.0.12"}
                ],
            }
        ],
    }
    packages, spec_version = SyftGenerator().parse_result(payload, "SPDX_JSON")
    assert spec_version == "SPDX-2.3"
    assert packages[0].ecosystem == "Debian"
    assert packages[0].purl == "pkg:deb/debian/openssl@3.0.12"


def test_sbom_format_aliases_are_accepted() -> None:
    assert normalize_sbom_format("cyclonedx-json") == "CYCLONEDX_JSON"
    assert normalize_sbom_format("CYCLONEDX_JSON") == "CYCLONEDX_JSON"
    assert normalize_sbom_format("spdx-json") == "SPDX_JSON"
    with pytest.raises(ExternalServiceError):
        normalize_sbom_format("xml")
