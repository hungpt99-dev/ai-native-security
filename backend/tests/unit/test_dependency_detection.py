"""Deterministic dependency change detection (no database, no network)."""

from __future__ import annotations

from pathlib import Path

from app.modules.sbom.dependencies import (
    BUILD_CONFIG,
    LOCKFILE,
    MANIFEST,
    classify_path,
    classify_paths,
    component_identity,
    dependency_fingerprint,
    describe_change,
    is_dependency_path,
    manifest_fingerprint,
    purl_identity,
    stable_purl,
)
from app.modules.scanners.syft import SbomPackageInfo


def test_manifest_and_lockfile_are_distinguished() -> None:
    package_json = classify_path("package.json")
    lock = classify_path("package-lock.json")
    assert package_json is not None and package_json.kind == MANIFEST
    assert lock is not None and lock.kind == LOCKFILE
    # A manifest is not a lockfile: both must be watched, neither implies the other.
    assert package_json.ecosystem == lock.ecosystem == "npm"


def test_supported_ecosystems_are_recognised() -> None:
    cases = {
        "pom.xml": "Maven",
        "build.gradle.kts": "Maven",
        "gradle.lockfile": "Maven",
        "yarn.lock": "npm",
        "pnpm-lock.yaml": "npm",
        "requirements-dev.txt": "PyPI",
        "poetry.lock": "PyPI",
        "uv.lock": "PyPI",
        "Pipfile.lock": "PyPI",
        "go.mod": "Go",
        "go.sum": "Go",
        "Cargo.lock": "crates.io",
        "services/api/Contoso.Api.csproj": "NuGet",
        "packages.lock.json": "NuGet",
        "Dockerfile": "Docker",
        "docker/Dockerfile.prod": "Docker",
        "docker-compose.override.yml": "Docker",
        "Gemfile.lock": "RubyGems",
        "composer.lock": "Packagist",
        "pubspec.lock": "Pub",
    }
    for path, ecosystem in cases.items():
        kind = classify_path(path)
        assert kind is not None, path
        assert kind.ecosystem == ecosystem, path


def test_business_logic_files_are_not_dependency_inputs() -> None:
    for path in (
        "src/app.py",
        "README.md",
        "tests/test_login.py",
        "package.json.bak",
        ".github/workflows/ci.yml",
        "docs/architecture.md",
    ):
        assert not is_dependency_path(path), path


def test_monorepo_multiple_manifests_are_all_classified() -> None:
    analysis = classify_paths(
        [
            "services/api/pom.xml",
            "services/web/package.json",
            "services/web/package-lock.json",
            "src/main/java/App.java",
        ]
    )
    assert analysis.affects_composition is True
    assert analysis.ecosystems == ["Maven", "npm"]
    assert {entry.kind for entry in analysis.dependency_files} == {MANIFEST, LOCKFILE}
    assert [entry.path for entry in analysis.dependency_files] == [
        "services/api/pom.xml",
        "services/web/package-lock.json",
        "services/web/package.json",
    ]


def test_renamed_manifest_reports_both_paths() -> None:
    analysis = classify_paths(["requirements.txt", "requirements-prod.txt"])
    assert len(analysis.dependency_files) == 2
    assert describe_change(analysis).startswith("2 dependency input(s) changed")


def test_deleted_manifest_still_counts_as_a_change() -> None:
    # A deletion arrives as a path with no content; it must not be ignored.
    analysis = classify_paths(["go.sum"])
    assert analysis.affects_composition is True
    assert analysis.dependency_files[0].kind == LOCKFILE


def test_business_logic_only_change_does_not_affect_composition() -> None:
    analysis = classify_paths(["src/service.py", "src/views.py", "CHANGELOG.md"])
    assert analysis.affects_composition is False
    assert analysis.dependency_files == []
    assert describe_change(analysis) == "no dependency inputs changed"


def _workspace(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def test_manifest_fingerprint_is_deterministic(tmp_path: Path) -> None:
    files = {
        "package.json": '{"dependencies": {"lodash": "4.17.21"}}',
        "package-lock.json": '{"lockfileVersion": 3}',
        "src/app.ts": "export const x = 1",
    }
    first = manifest_fingerprint(_workspace(tmp_path / "a", files))
    second = manifest_fingerprint(_workspace(tmp_path / "b", files))
    assert first.fingerprint is not None
    assert first.fingerprint == second.fingerprint
    assert first.files == ["package-lock.json", "package.json"]


def test_lockfile_change_changes_the_manifest_fingerprint(tmp_path: Path) -> None:
    base = {"package.json": "{}", "package-lock.json": '{"v": 1}'}
    changed = {"package.json": "{}", "package-lock.json": '{"v": 2}'}
    before = manifest_fingerprint(_workspace(tmp_path / "a", base))
    after = manifest_fingerprint(_workspace(tmp_path / "b", changed))
    assert before.fingerprint != after.fingerprint


def test_manifest_fingerprint_ignores_vendored_trees(tmp_path: Path) -> None:
    root = _workspace(
        tmp_path,
        {
            "package.json": "{}",
            "node_modules/dep/package.json": '{"name": "dep"}',
            ".venv/lib/requirements.txt": "requests==1.0",
            "vendor/go.mod": "module vendor",
        },
    )
    result = manifest_fingerprint(root)
    assert result.files == ["package.json"]


def test_manifest_fingerprint_without_dependency_files_is_none(tmp_path: Path) -> None:
    root = _workspace(tmp_path, {"src/main.py": "print('hi')"})
    result = manifest_fingerprint(root)
    assert result.fingerprint is None
    assert result.files == []


def test_manifest_fingerprint_reports_truncation(tmp_path: Path) -> None:
    files = {f"service-{index}/package.json": "{}" for index in range(5)}
    result = manifest_fingerprint(_workspace(tmp_path, files), max_files=2)
    assert result.truncated is True
    assert len(result.files) == 2


def test_purl_identity_is_version_independent_and_qualifier_free() -> None:
    assert stable_purl("pkg:pypi/requests@2.31.0?arch=any") == "pkg:pypi/requests@2.31.0"
    assert purl_identity("pkg:pypi/requests@2.31.0?arch=any") == "pkg:pypi/requests"
    assert purl_identity("pkg:npm/%40scope/pkg@1.0.0") == purl_identity(
        "pkg:npm/%40scope/pkg@2.0.0"
    )
    assert component_identity(
        name="requests", version="2.31.0", ecosystem="PyPI", purl="pkg:pypi/requests@2.31.0"
    ) == ("pkg:pypi/requests", "purl")


def test_identity_falls_back_to_ecosystem_then_name() -> None:
    assert component_identity(
        name="lodash", version="4.17.21", ecosystem="npm", purl=None
    ) == ("npm:lodash", "ecosystem_name")
    assert component_identity(name="mystery", version="1", ecosystem=None, purl=None) == (
        "name:mystery",
        "name_only",
    )


def test_dependency_fingerprint_distinguishes_ecosystems() -> None:
    python = [SbomPackageInfo(name="requests", version="2.31.0", ecosystem="PyPI")]
    npm = [SbomPackageInfo(name="requests", version="2.31.0", ecosystem="npm")]
    assert dependency_fingerprint(python) != dependency_fingerprint(npm)


def test_dependency_fingerprint_is_order_and_qualifier_independent() -> None:
    left = [
        SbomPackageInfo(name="a", version="1.0", purl="pkg:pypi/a@1.0"),
        SbomPackageInfo(name="b", version="2.0", purl="pkg:pypi/b@2.0?arch=any"),
    ]
    right = [
        SbomPackageInfo(name="b", version="2.0", purl="pkg:pypi/b@2.0"),
        SbomPackageInfo(name="a", version="1.0", purl="pkg:pypi/a@1.0"),
    ]
    assert dependency_fingerprint(left) == dependency_fingerprint(right)


def test_dependency_fingerprint_changes_with_version() -> None:
    before = [SbomPackageInfo(name="flask", version="3.0.0", purl="pkg:pypi/flask@3.0.0")]
    after = [SbomPackageInfo(name="flask", version="3.0.3", purl="pkg:pypi/flask@3.0.3")]
    assert dependency_fingerprint(before) != dependency_fingerprint(after)
    assert dependency_fingerprint([]) is None


def test_docker_base_image_change_is_classified() -> None:
    analysis = classify_paths(["Dockerfile", "src/app.py"])
    assert analysis.affects_composition is True
    assert analysis.dependency_files[0].kind == BUILD_CONFIG
    assert analysis.dependency_files[0].ecosystem == "Docker"
