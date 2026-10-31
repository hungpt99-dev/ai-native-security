"""Scan orchestration: lifecycle, normalization, failure semantics.

External tools are replaced by controlled fixtures so behaviour is verified
without network access or scanner binaries.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.enums import ScannerExecutionStatus, ScanStatus
from app.modules.assets.service import resolve_access_token
from app.modules.findings.models import Finding
from app.modules.sbom.models import Sbom, SbomPackage
from app.modules.scanners.base import NormalizedFinding, ScannerRun
from app.modules.scanners.syft import SbomDocument, SbomPackageInfo
from app.modules.scans.models import ScannerExecution
from app.modules.scans.service import create_scan
from app.workers import pipeline
from app.workers.checkout import Checkout

TRIVY_FINDING = NormalizedFinding(
    scanner="trivy",
    rule_id="CVE-2024-0001",
    title="Vulnerable dependency",
    category="vulnerability",
    severity="HIGH",
    package_name="requests",
    package_version="2.19.0",
    cve_id="CVE-2024-0001",
    cvss_score=7.5,
)

SECRET_FINDING = NormalizedFinding(
    scanner="gitleaks",
    rule_id="aws-access-token",
    title="AWS Access Token",
    category="secret",
    severity="HIGH",
    file_path="deploy/env.sh",
    line_number=3,
)


class FakeScanner:
    def __init__(self, name: str, findings: list[NormalizedFinding], status: str = "SUCCESS") -> None:
        self.name = name
        self._findings = findings
        self._status = status

    def run(self, workspace: Path, report_dir: Path) -> ScannerRun:
        report_dir.mkdir(parents=True, exist_ok=True)
        return ScannerRun(
            scanner=self.name,
            status=self._status,
            findings=self._findings if self._status == "SUCCESS" else [],
            version="test-1.0",
            exit_code=0,
            duration_seconds=0.01,
            command={"argv": [self.name, "scan"]},
        )


class FakeSyft:
    def generate(
        self, workspace: Path, output_dir: Path, sbom_format: str = "CYCLONEDX_JSON"
    ) -> SbomDocument:
        output_dir.mkdir(parents=True, exist_ok=True)
        return SbomDocument(
            content=b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}',
            format="CYCLONEDX_JSON",
            spec_version="1.5",
            tool_version="syft-test",
            packages=[
                SbomPackageInfo(
                    name="requests",
                    version="2.19.0",
                    ecosystem="PyPI",
                    purl="pkg:pypi/requests@2.19.0",
                    license="Apache-2.0",
                    source_type="python",
                )
            ],
        )


@pytest.fixture()
def fake_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    def fake_clone(*, repo_url, branch, token, destination):  # noqa: ANN001, ARG001
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "requirements.txt").write_text("requests==2.19.0\n")
        return Checkout(
            path=destination, branch=branch, commit_sha="deadbeefcafe", provider="github"
        )

    def install(scanners):  # noqa: ANN001
        monkeypatch.setattr(pipeline, "clone_repository", fake_clone)
        monkeypatch.setattr(pipeline, "get_syft", lambda: FakeSyft())
        monkeypatch.setattr(pipeline, "enabled_scanners", lambda: scanners)
        monkeypatch.setattr(pipeline, "correlate_packages", lambda *args, **kwargs: [])

    return install


def test_scan_completes_and_persists_results(db: Session, asset_factory, fake_environment) -> None:
    fake_environment([FakeScanner("trivy", [TRIVY_FINDING]), FakeScanner("gitleaks", [SECRET_FINDING])])
    asset = asset_factory()
    scan = create_scan(db, asset)
    db.commit()

    pipeline.execute_scan(db, scan.id)
    db.refresh(scan)

    assert scan.status == ScanStatus.COMPLETED.value
    assert scan.commit_sha == "deadbeefcafe"
    assert scan.total_findings == 2
    assert scan.high_count == 2
    assert scan.new_findings == 2
    assert scan.duration_seconds is not None

    executions = db.query(ScannerExecution).filter(ScannerExecution.scan_id == scan.id).all()
    assert {execution.scanner for execution in executions} == {"syft", "trivy", "gitleaks"}
    assert all(execution.status == ScannerExecutionStatus.SUCCESS.value for execution in executions)

    sbom = db.query(Sbom).filter(Sbom.scan_id == scan.id).one()
    assert sbom.package_count == 1
    assert db.query(SbomPackage).filter(SbomPackage.sbom_id == sbom.id).count() == 1

    assert db.query(Finding).filter(Finding.asset_id == asset.id).count() == 2
    db.refresh(asset)
    assert asset.last_scan_status == ScanStatus.COMPLETED.value

    workspace = Path(pipeline.get_settings().workspace_root) / f"scan-{scan.id}"
    assert not workspace.exists(), "workspace must be cleaned up"


def test_failed_scanner_fails_scan_and_blocks_resolution(
    db: Session, asset_factory, fake_environment
) -> None:
    fake_environment([FakeScanner("trivy", [TRIVY_FINDING])])
    asset = asset_factory()
    first = create_scan(db, asset)
    db.commit()
    pipeline.execute_scan(db, first.id)

    # Second scan: trivy breaks, so the previous finding must stay OPEN.
    fake_environment([FakeScanner("trivy", [], status="FAILED")])
    second = create_scan(db, asset)
    db.commit()
    pipeline.execute_scan(db, second.id)
    db.refresh(second)

    assert second.status == ScanStatus.FAILED.value
    assert "trivy" in (second.error_message or "")
    finding = db.query(Finding).one()
    assert finding.status == "OPEN"


def test_canceled_scan_is_not_executed(db: Session, asset_factory, fake_environment) -> None:
    fake_environment([FakeScanner("trivy", [])])
    asset = asset_factory()
    scan = create_scan(db, asset)
    scan.status = ScanStatus.CANCELED.value
    db.commit()

    pipeline.execute_scan(db, scan.id)
    db.refresh(scan)
    assert scan.status == ScanStatus.CANCELED.value
    assert db.query(ScannerExecution).filter(ScannerExecution.scan_id == scan.id).count() == 0


def test_duplicate_active_scan_is_rejected(db: Session, asset_factory) -> None:
    from app.core.errors import ConflictError

    asset = asset_factory()
    create_scan(db, asset)
    db.commit()
    with pytest.raises(ConflictError):
        create_scan(db, asset)


def test_access_token_decryption_roundtrip(db: Session, asset_factory) -> None:
    asset = asset_factory(access_token="ghp_tokentest1234567890")
    assert resolve_access_token(db, asset) == "ghp_tokentest1234567890"


def test_scan_unknown_asset_returns_404(client, db: Session) -> None:
    response = client.get(f"/api/v1/scans/{uuid.uuid4()}")
    assert response.status_code == 404
