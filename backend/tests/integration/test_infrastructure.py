"""Infrastructure assessment: parsers, target validation, execution, findings."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ValidationError
from app.modules.findings.models import Finding
from app.modules.infrastructure import scanners, service
from app.modules.scanners.base import NormalizedFinding
from app.modules.scanners.execution import ProcessResult
from app.workers.models import Job

TRIVY_CONFIG = {
    "Results": [
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Description": "Running as root",
                    "Message": "Specify a non-root user",
                    "Resolution": "Add USER",
                    "Severity": "HIGH",
                    "CauseMetadata": {"StartLine": 3, "EndLine": 3},
                    "References": ["https://example.test/DS002"],
                }
            ],
        }
    ]
}

CHECKOV = [
    {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 bucket public",
                    "file_path": "/main.tf",
                    "file_line_range": [10, 12],
                    "resource": "aws_s3_bucket.public",
                    "guideline": "https://example.test/CKV_AWS_20",
                }
            ]
        },
    }
]

TRIVY_IMAGE = {
    "Results": [
        {
            "Target": "ghcr.io/acme/api:1.0 (alpine 3.19)",
            "Class": "os-pkgs",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.1.0",
                    "FixedVersion": "3.1.1",
                    "Severity": "CRITICAL",
                    "Title": "OpenSSL issue",
                    "PkgIdentifier": {"PURL": "pkg:apk/alpine/openssl@3.1.0"},
                }
            ],
        }
    ]
}


def test_trivy_config_parser_maps_misconfigurations():
    findings = scanners.TrivyConfigAdapter().parse_result(TRIVY_CONFIG, target="repo")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DS002"
    assert finding.severity == "HIGH"
    assert finding.file_path == "Dockerfile"
    assert finding.line_number == 3
    assert finding.metadata["resolution"] == "Add USER"


def test_checkov_parser_does_not_invent_missing_severity():
    findings = scanners.CheckovAdapter().parse_result(CHECKOV, target="repo")
    assert findings[0].rule_id == "CKV_AWS_20"
    assert findings[0].severity == "UNKNOWN"
    assert findings[0].line_number == 10


def test_trivy_image_parser_keeps_package_identity():
    findings = scanners.TrivyImageAdapter().parse_result(TRIVY_IMAGE, target="ghcr.io/acme/api:1.0")
    finding = findings[0]
    assert finding.cve_id == "CVE-2024-1234"
    assert finding.package_name == "openssl"
    assert finding.purl == "pkg:apk/alpine/openssl@3.1.0"


def test_image_registry_allowlist_blocks_internal_targets(db: Session):
    with pytest.raises(ValidationError):
        service.create_scan(
            db,
            target_kind="CONTAINER_IMAGE",
            scanner="trivy-image",
            target_ref="registry.internal:5000/secret/app:1.0",
        )


def test_image_scan_is_created_and_queued(db: Session):
    row = service.create_scan(
        db,
        target_kind="CONTAINER_IMAGE",
        scanner="trivy-image",
        target_ref="ghcr.io/acme/api:1.0",
    )
    db.commit()
    assert row.status == "PENDING"
    job = db.execute(select(Job).where(Job.kind == "INFRA_SCAN")).scalar_one()
    assert job.payload["scan_id"] == str(row.id)
    with pytest.raises(ConflictError):
        service.create_scan(
            db,
            target_kind="CONTAINER_IMAGE",
            scanner="trivy-image",
            target_ref="ghcr.io/acme/api:1.0",
        )


def test_iac_scan_requires_a_repository_asset(db: Session):
    from app.modules.assets.models import Asset

    asset = Asset(
        name="image",
        kind="CONTAINER_IMAGE",
        repo_url=None,
        external_ref="docker://ghcr.io/acme/other:1.0",
        provider="NONE",
    )
    db.add(asset)
    db.flush()
    with pytest.raises(ValidationError):
        service.create_scan(
            db,
            target_kind="IAC_REPOSITORY",
            scanner="trivy-config",
            asset_id=asset.id,
        )


class _FakeAdapter:
    name = "trivy-image"
    target_kind = "CONTAINER_IMAGE"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def check_availability(self):
        return scanners.InfraAvailability(True, "0.0.0-fake", None)

    def run(self, target, report_path, *, cwd):
        if self.fail:
            raise RuntimeError("scanner exploded")
        return ProcessResult(command=["fake"], exit_code=0, stdout="", stderr="", duration_seconds=0.01)

    def read(self, report_path):
        return {}

    def accepts_exit_code(self, code: int) -> bool:
        return code in {0, 1}

    def parse_result(self, payload, *, target):
        return [
            NormalizedFinding(
                scanner="trivy-image",
                rule_id="CVE-2024-0002",
                title="Vulnerable openssl",
                category="container_vulnerability",
                severity="HIGH",
                package_name="openssl",
                package_version="3.1.0",
                cve_id="CVE-2024-0002",
            )
        ]


def test_execution_records_findings_on_the_image_asset(db: Session, monkeypatch):
    row = service.create_scan(
        db,
        target_kind="CONTAINER_IMAGE",
        scanner="trivy-image",
        target_ref="ghcr.io/acme/api:2.0",
        requested_by="tester",
    )
    db.commit()
    monkeypatch.setattr(service.scanners, "get_adapter", lambda name: _FakeAdapter())

    service.execute_scan(db, row.id)
    db.commit()
    db.refresh(row)
    assert row.status == "COMPLETED"
    assert row.total_findings == 1
    assert row.high_count == 1
    finding = db.execute(
        select(Finding).where(Finding.rule_id == "CVE-2024-0002")
    ).scalar_one()
    assert finding.asset_id == row.asset_id
    assert finding.discovery_source == "INFRASTRUCTURE_SCAN"
    assert finding.package_name == "openssl"


def test_execution_failure_is_recorded_not_swallowed(db: Session, monkeypatch):
    row = service.create_scan(
        db,
        target_kind="CONTAINER_IMAGE",
        scanner="trivy-image",
        target_ref="ghcr.io/acme/api:3.0",
    )
    db.commit()
    monkeypatch.setattr(service.scanners, "get_adapter", lambda name: _FakeAdapter(fail=True))
    service.execute_scan(db, row.id)
    db.commit()
    db.refresh(row)
    assert row.status == "FAILED"
    assert "scanner exploded" in (row.error_message or "")
    assert db.execute(select(Finding)).scalar_one_or_none() is None


def test_infrastructure_api_lists_scans_and_scanners(client):
    created = client.post(
        "/api/v1/infrastructure/scans",
        json={
            "target_kind": "CONTAINER_IMAGE",
            "scanner": "trivy-image",
            "target_ref": "ghcr.io/acme/api:4.0",
        },
    )
    assert created.status_code == 201
    listing = client.get("/api/v1/infrastructure/scans").json()
    assert listing["total"] == 1
    assert client.get("/api/v1/infrastructure/summary").status_code == 200
    assert isinstance(client.get("/api/v1/infrastructure/scanners").json(), list)

    blocked = client.post(
        "/api/v1/infrastructure/scans",
        json={
            "target_kind": "CONTAINER_IMAGE",
            "scanner": "trivy-image",
            "target_ref": "registry.internal/secret:1.0",
        },
    )
    assert blocked.status_code == 422


def test_infrastructure_assets_are_registrable(client):
    response = client.post(
        "/api/v1/infrastructure/assets",
        json={
            "name": "api-prod-01",
            "kind": "HOST",
            "external_ref": "host://api-prod-01",
        },
    )
    assert response.status_code == 201
    assert response.json()["kind"] == "HOST"
    listing = client.get("/api/v1/infrastructure/assets").json()
    assert listing["total"] == 1
