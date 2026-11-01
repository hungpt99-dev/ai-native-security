"""Test doubles for the SBOM lifecycle integration tests.

Only *external* boundaries are faked (GitHub/GitLab REST, git clone, Syft
binary). PostgreSQL, the queue, the job table, findings and storage are real, as
the project's testing rules require.
"""

from __future__ import annotations

import shutil
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.modules.git_provider.client import CommitComparison, GitProviderError
from app.modules.scanners.syft import SbomDocument, SbomPackageInfo
from app.modules.vulnerabilities.models import (
    Vulnerability,
    VulnerabilityAffectedPackage,
    VulnerabilityEpss,
)
from app.workers.checkout import Checkout


class FakeProviderClient:
    """Stand-in for ``RepositoryProviderClient`` with scripted answers."""

    def __init__(
        self,
        *,
        head: str = "a" * 40,
        files: list[str] | None = None,
        truncated: bool = False,
        fail: bool = False,
        head_error: str = "provider unreachable",
    ) -> None:
        self.head = head
        self.files = files if files is not None else []
        self.truncated = truncated
        self.fail = fail
        self.head_error = head_error
        self.head_calls = 0
        self.compare_calls = 0

    def head_commit(self, reference: Any, branch: str, *, token: str | None = None) -> str:
        self.head_calls += 1
        if self.fail:
            raise GitProviderError(self.head_error)
        return self.head

    def compare(
        self,
        reference: Any,
        base_sha: str,
        head_sha: str,
        *,
        token: str | None = None,
    ) -> CommitComparison:
        self.compare_calls += 1
        if self.fail:
            raise GitProviderError(self.head_error)
        return CommitComparison(
            base_sha=base_sha, head_sha=head_sha, files=list(self.files), truncated=self.truncated
        )


def package(
    name: str, version: str, *, ecosystem: str = "PyPI", purl: str | None = None
) -> SbomPackageInfo:
    return SbomPackageInfo(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=purl or f"pkg:{ecosystem.lower()}/{name}@{version}",
    )


def document(
    packages: list[SbomPackageInfo],
    *,
    content: bytes | None = None,
    direct_keys: set[tuple[str, str]] | None = None,
) -> SbomDocument:
    body = content or (
        '{"bomFormat":"CycloneDX","specVersion":"1.5","components":['
        + ",".join(f'{{"name":"{item.name}","version":"{item.version}"}}' for item in packages)
        + "]}"
    ).encode()
    return SbomDocument(
        content=body,
        format="CYCLONEDX_JSON",
        spec_version="1.5",
        tool_version="syft-test",
        packages=packages,
        direct_package_keys=direct_keys or set(),
    )


class FakeSyft:
    """Returns a fixed document; records how many times it was invoked."""

    def __init__(self, doc: SbomDocument | None = None, *, fail: Exception | None = None) -> None:
        self.doc = doc or document([package("requests", "2.31.0")])
        self.fail = fail
        self.calls = 0

    def generate(
        self, workspace: Path, output_dir: Path, *, sbom_format: str = "cyclonedx-json"
    ) -> SbomDocument:
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        output_dir.mkdir(parents=True, exist_ok=True)
        return self.doc


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def install_fake_checkout(
    monkeypatch: Any, source: Path, commit_sha: str = "c" * 40, branch: str = "main"
) -> None:
    """Replace the real clone with a workspace copy (no network, no git)."""

    def fake_clone(
        *, repo_url: str, branch: str, token: str | None, destination: Path
    ) -> Checkout:
        if destination.exists():
            for child in destination.iterdir():
                shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink()
        shutil.copytree(source, destination, dirs_exist_ok=True)
        return Checkout(
            path=destination, branch=branch, commit_sha=commit_sha, provider="github"
        )

    monkeypatch.setattr("app.modules.sbom.lifecycle.clone_repository", fake_clone)


@dataclass
class IntelSpec:
    osv_id: str
    package_name: str
    ecosystem: str = "PyPI"
    cve_id: str | None = None
    severity: str = "HIGH"
    cvss_score: float | None = 7.5
    is_kev: bool = False
    ranges: list[dict[str, Any]] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    source: str = "OSV"
    summary: str = "A test vulnerability"
    references: list[str] = field(default_factory=list)


def add_vulnerability(db: Session, spec: IntelSpec) -> Vulnerability:
    """Persist intelligence exactly as the sync jobs would."""
    vulnerability = Vulnerability(
        source=spec.source,
        source_id=spec.osv_id,
        cve_id=spec.cve_id,
        osv_id=spec.osv_id if spec.source == "OSV" else None,
        summary=spec.summary,
        description="Test vulnerability used by the SBOM reassessment tests.",
        cvss_score=spec.cvss_score,
        cvss_vector=None,
        severity=spec.severity,
        published_at=datetime.now(UTC),
        modified_at=datetime.now(UTC),
        is_kev=spec.is_kev,
    )
    db.add(vulnerability)
    db.flush()
    db.add(
        VulnerabilityAffectedPackage(
            vulnerability_id=vulnerability.id,
            ecosystem=spec.ecosystem,
            package_name=spec.package_name,
            purl=None,
            affected_versions=list(spec.affected_versions),
            fixed_versions=list(spec.fixed_versions),
            version_ranges=list(spec.ranges),
        )
    )
    db.flush()
    return vulnerability


def affected_range(introduced: str, fixed: str) -> list[dict[str, Any]]:
    return [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}]


def add_epss(db: Session, cve_id: str, score: float, percentile: float = 0.9) -> None:
    db.add(
        VulnerabilityEpss(
            cve_id=cve_id,
            score=score,
            percentile=percentile,
            model_version="test",
            scored_date=datetime.now(UTC).date(),
        )
    )
    db.flush()


def make_snapshot(
    db: Session,
    *,
    asset_id: uuid.UUID,
    packages: list[SbomPackageInfo],
    commit_sha: str = "a" * 40,
    reason: str = "FULL_SCAN",
    dependency_fingerprint: str | None = None,
) -> Any:
    from app.modules.sbom import service

    return service.store_sbom(
        db,
        asset_id=asset_id,
        scan_id=None,
        document=document(packages),
        commit_sha=commit_sha,
        branch="main",
        creation_reason=reason,
        dependency_fingerprint=dependency_fingerprint,
    )
