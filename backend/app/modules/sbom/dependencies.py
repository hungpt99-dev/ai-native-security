"""Deterministic dependency-change detection.

Two independent fingerprints and one path classifier live here:

* **manifest fingerprint** — hash of the dependency manifests, lockfiles and
  build configuration present in a checked-out workspace. It answers "did the
  declared inputs change".
* **dependency fingerprint** — hash of the resolved component inventory
  (ecosystem/name/version or purl). It answers "did the graph that the SBOM
  actually recorded change".
* **path classification** — given a list of changed repository paths, decide
  whether any of them can influence software composition.

A manifest is *not* a lockfile: ``package.json`` can stay byte-identical while
``package-lock.json`` resolves a different transitive graph, so both contribute
to the manifest fingerprint and both are classified as dependency inputs.

Nothing here executes a scanner, clones a repository or calls a model.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from app.core.logging import get_logger

logger = get_logger(__name__)

MANIFEST = "MANIFEST"
LOCKFILE = "LOCKFILE"
BUILD_CONFIG = "BUILD_CONFIG"

#: Directories that never contain project dependencies worth hashing.
SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "out",
        ".next",
        ".nuxt",
        ".terraform",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".gradle",
        ".idea",
        ".vscode",
        "bin",
        "obj",
    }
)


@dataclass(frozen=True)
class DependencyFileKind:
    ecosystem: str
    kind: str
    description: str


#: Exact basenames. Case matters on Linux checkouts, and these names are fixed
#: by their ecosystems, so they are matched verbatim.
EXACT_FILES: dict[str, DependencyFileKind] = {
    # Maven / Gradle
    "pom.xml": DependencyFileKind("Maven", MANIFEST, "Maven project model"),
    "build.gradle": DependencyFileKind("Maven", BUILD_CONFIG, "Gradle build script"),
    "build.gradle.kts": DependencyFileKind("Maven", BUILD_CONFIG, "Gradle Kotlin build script"),
    "settings.gradle": DependencyFileKind("Maven", BUILD_CONFIG, "Gradle module layout"),
    "settings.gradle.kts": DependencyFileKind("Maven", BUILD_CONFIG, "Gradle module layout"),
    "gradle.properties": DependencyFileKind("Maven", BUILD_CONFIG, "Gradle properties"),
    "gradle.lockfile": DependencyFileKind("Maven", LOCKFILE, "Gradle dependency lock"),
    "libs.versions.toml": DependencyFileKind("Maven", MANIFEST, "Gradle version catalog"),
    # Node.js
    "package.json": DependencyFileKind("npm", MANIFEST, "npm manifest"),
    "package-lock.json": DependencyFileKind("npm", LOCKFILE, "npm lockfile"),
    "npm-shrinkwrap.json": DependencyFileKind("npm", LOCKFILE, "npm shrinkwrap"),
    "yarn.lock": DependencyFileKind("npm", LOCKFILE, "Yarn lockfile"),
    "pnpm-lock.yaml": DependencyFileKind("npm", LOCKFILE, "pnpm lockfile"),
    "pnpm-workspace.yaml": DependencyFileKind("npm", BUILD_CONFIG, "pnpm workspace layout"),
    ".npmrc": DependencyFileKind("npm", BUILD_CONFIG, "npm registry configuration"),
    ".yarnrc.yml": DependencyFileKind("npm", BUILD_CONFIG, "Yarn registry configuration"),
    # Python
    "pyproject.toml": DependencyFileKind("PyPI", MANIFEST, "Python project metadata"),
    "poetry.lock": DependencyFileKind("PyPI", LOCKFILE, "Poetry lockfile"),
    "uv.lock": DependencyFileKind("PyPI", LOCKFILE, "uv lockfile"),
    "Pipfile": DependencyFileKind("PyPI", MANIFEST, "Pipenv manifest"),
    "Pipfile.lock": DependencyFileKind("PyPI", LOCKFILE, "Pipenv lockfile"),
    "setup.py": DependencyFileKind("PyPI", MANIFEST, "setuptools manifest"),
    "setup.cfg": DependencyFileKind("PyPI", MANIFEST, "setuptools configuration"),
    "environment.yml": DependencyFileKind("PyPI", MANIFEST, "Conda environment"),
    "environment.yaml": DependencyFileKind("PyPI", MANIFEST, "Conda environment"),
    # Go
    "go.mod": DependencyFileKind("Go", MANIFEST, "Go module file"),
    "go.sum": DependencyFileKind("Go", LOCKFILE, "Go checksum database"),
    "go.work": DependencyFileKind("Go", BUILD_CONFIG, "Go workspace"),
    # Rust
    "Cargo.toml": DependencyFileKind("crates.io", MANIFEST, "Cargo manifest"),
    "Cargo.lock": DependencyFileKind("crates.io", LOCKFILE, "Cargo lockfile"),
    # .NET
    "packages.lock.json": DependencyFileKind("NuGet", LOCKFILE, ".NET package lock"),
    "packages.config": DependencyFileKind("NuGet", MANIFEST, "NuGet packages.config"),
    "Directory.Packages.props": DependencyFileKind("NuGet", BUILD_CONFIG, "central package versions"),
    "Directory.Build.props": DependencyFileKind("NuGet", BUILD_CONFIG, "MSBuild properties"),
    "global.json": DependencyFileKind("NuGet", BUILD_CONFIG, ".NET SDK pin"),
    # Ruby
    "Gemfile": DependencyFileKind("RubyGems", MANIFEST, "Bundler manifest"),
    "Gemfile.lock": DependencyFileKind("RubyGems", LOCKFILE, "Bundler lockfile"),
    # PHP
    "composer.json": DependencyFileKind("Packagist", MANIFEST, "Composer manifest"),
    "composer.lock": DependencyFileKind("Packagist", LOCKFILE, "Composer lockfile"),
    # Swift / Dart / Elixir
    "Package.swift": DependencyFileKind("SwiftURL", MANIFEST, "Swift package manifest"),
    "Package.resolved": DependencyFileKind("SwiftURL", LOCKFILE, "Swift resolved packages"),
    "pubspec.yaml": DependencyFileKind("Pub", MANIFEST, "Dart package manifest"),
    "pubspec.lock": DependencyFileKind("Pub", LOCKFILE, "Dart lockfile"),
    "mix.exs": DependencyFileKind("Hex", MANIFEST, "Elixir mix manifest"),
    "mix.lock": DependencyFileKind("Hex", LOCKFILE, "Elixir lockfile"),
    # Containers
    "docker-compose.yml": DependencyFileKind("Docker", BUILD_CONFIG, "Compose base images"),
    "docker-compose.yaml": DependencyFileKind("Docker", BUILD_CONFIG, "Compose base images"),
    "compose.yml": DependencyFileKind("Docker", BUILD_CONFIG, "Compose base images"),
    "compose.yaml": DependencyFileKind("Docker", BUILD_CONFIG, "Compose base images"),
    "Dockerfile": DependencyFileKind("Docker", BUILD_CONFIG, "Container base image"),
}

#: Glob patterns for families of manifest names (monorepos, multi-stage images).
GLOB_FILES: tuple[tuple[str, DependencyFileKind], ...] = (
    ("requirements*.txt", DependencyFileKind("PyPI", MANIFEST, "pip requirements")),
    ("constraints*.txt", DependencyFileKind("PyPI", MANIFEST, "pip constraints")),
    ("*.csproj", DependencyFileKind("NuGet", MANIFEST, ".NET project file")),
    ("*.fsproj", DependencyFileKind("NuGet", MANIFEST, ".NET project file")),
    ("*.vbproj", DependencyFileKind("NuGet", MANIFEST, ".NET project file")),
    ("*.gemspec", DependencyFileKind("RubyGems", MANIFEST, "Ruby gem specification")),
    ("Dockerfile.*", DependencyFileKind("Docker", BUILD_CONFIG, "Container base image")),
    ("*.dockerfile", DependencyFileKind("Docker", BUILD_CONFIG, "Container base image")),
    ("docker-compose*.yml", DependencyFileKind("Docker", BUILD_CONFIG, "Compose base images")),
    ("docker-compose*.yaml", DependencyFileKind("Docker", BUILD_CONFIG, "Compose base images")),
)


@dataclass(frozen=True)
class MatchedDependencyFile:
    path: str
    ecosystem: str
    kind: str
    description: str


@dataclass
class DependencyPathAnalysis:
    """Result of classifying a set of changed repository paths."""

    dependency_files: list[MatchedDependencyFile] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    systems: list[str] = field(default_factory=list)
    total_paths: int = 0

    @property
    def affects_composition(self) -> bool:
        return bool(self.dependency_files)


@dataclass
class ManifestFingerprint:
    fingerprint: str | None
    files: list[str] = field(default_factory=list)
    truncated: bool = False
    #: Bytes hashed; useful for operational logs, never for decisions.
    bytes_read: int = 0


def classify_path(path: str) -> DependencyFileKind | None:
    """Return the dependency file kind for one repository-relative path."""
    name = path.rsplit("/", 1)[-1]
    kind = EXACT_FILES.get(name)
    if kind is not None:
        return kind
    lowered = name.lower()
    for pattern, candidate in GLOB_FILES:
        if fnmatch.fnmatchcase(lowered, pattern.lower()):
            return candidate
    return None


def is_dependency_path(path: str) -> bool:
    return classify_path(path) is not None


def is_manifest_path(path: str) -> bool:
    """True for any dependency input (manifest, lockfile or build config)."""
    return is_dependency_path(path)


def classify_paths(paths: Iterable[str]) -> DependencyPathAnalysis:
    """Classify changed paths by ecosystem/build system.

    Deleted, renamed and newly added files all arrive as plain path strings, so
    a rename shows up as two paths and both are classified.
    """
    matched: dict[str, MatchedDependencyFile] = {}
    ecosystems: set[str] = set()
    systems: set[str] = set()
    total = 0
    for raw in paths:
        path = str(raw or "").strip()
        if not path:
            continue
        total += 1
        kind = classify_path(path)
        if kind is None:
            continue
        matched[path] = MatchedDependencyFile(
            path=path,
            ecosystem=kind.ecosystem,
            kind=kind.kind,
            description=kind.description,
        )
        ecosystems.add(kind.ecosystem)
        systems.add(kind.kind)
    return DependencyPathAnalysis(
        dependency_files=[matched[key] for key in sorted(matched)],
        ecosystems=sorted(ecosystems),
        systems=sorted(systems),
        total_paths=total,
    )


def _hash_file(path: Path, *, max_bytes: int) -> tuple[str, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    if not path.is_file() or stat.st_size > max_bytes:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest(), len(data)


def manifest_fingerprint(
    workspace: Path,
    *,
    max_files: int = 200,
    max_bytes: int = 4 * 1024 * 1024,
) -> ManifestFingerprint:
    """Hash every dependency input file in ``workspace``.

    Deterministic for a given tree: files are sorted by POSIX relative path and
    each contributes ``path\\0sha256``. Oversized or unreadable files are
    recorded as ``unreadable`` rather than silently omitted, and the result is
    marked ``truncated`` when the file ceiling is reached.
    """
    if not workspace or not workspace.exists():
        return ManifestFingerprint(fingerprint=None)

    entries: list[tuple[str, str]] = []
    files: list[str] = []
    truncated = False
    bytes_read = 0

    for root, dirnames, filenames in os.walk(workspace):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRECTORIES)
        for filename in sorted(filenames):
            if not is_dependency_path(filename):
                continue
            absolute = Path(root) / filename
            try:
                relative = absolute.relative_to(workspace).as_posix()
            except ValueError:  # pragma: no cover - defensive
                continue
            if len(files) >= max_files:
                truncated = True
                break
            hashed = _hash_file(absolute, max_bytes=max_bytes)
            files.append(relative)
            if hashed is None:
                entries.append((relative, "unreadable"))
                continue
            digest, size = hashed
            entries.append((relative, digest))
            bytes_read += size
        if truncated:
            break

    if not entries:
        return ManifestFingerprint(fingerprint=None, files=[], truncated=False)

    payload = "\n".join(f"{path}\0{digest}" for path, digest in sorted(entries))
    return ManifestFingerprint(
        fingerprint=hashlib.sha256(payload.encode()).hexdigest(),
        files=sorted(files),
        truncated=truncated,
        bytes_read=bytes_read,
    )


def stable_purl(purl: str | None) -> str | None:
    """PURL without qualifiers/subpath, lowercase type/namespace/name.

    Qualifiers (``?arch=amd64``) describe the build environment, not identity:
    keeping them would make two runs of the same inventory look different.
    """
    if not purl:
        return None
    value = str(purl).strip()
    if not value:
        return None
    value = value.split("#", 1)[0].split("?", 1)[0]
    if not value.startswith("pkg:"):
        return value
    body = value[4:]
    last_segment = body.rsplit("/", 1)[-1]
    if "@" in last_segment:
        head, version = body.rsplit("@", 1)
        return f"pkg:{head.lower()}@{version}"
    return f"pkg:{body.lower()}"


def purl_identity(purl: str | None) -> str | None:
    """Version-independent component identity derived from a PURL."""
    stable = stable_purl(purl)
    if not stable:
        return None
    if not stable.startswith("pkg:"):
        return stable
    body = stable[4:]
    last_segment = body.rsplit("/", 1)[-1]
    if "@" in last_segment:
        head, _version = body.rsplit("@", 1)
        return f"pkg:{head}"
    return stable


def component_identity(
    *, name: str, version: str, ecosystem: str | None, purl: str | None
) -> tuple[str, str]:
    """Return ``(identity, basis)`` for a component.

    Preference order: PURL (version-stripped) → ecosystem-qualified name →
    name only. Ecosystem is never dropped when it is known, because two
    ecosystems can legitimately ship a package with the same name.
    """
    identity = purl_identity(purl)
    if identity:
        return identity, "purl"
    normalized_name = (name or "").strip().lower()
    if ecosystem:
        return f"{ecosystem.strip().lower()}:{normalized_name}", "ecosystem_name"
    return f"name:{normalized_name}", "name_only"


def dependency_fingerprint(
    packages: Sequence[object],
) -> str | None:
    """Hash the resolved component inventory.

    Accepts anything with ``name``/``version``/``ecosystem``/``purl`` attributes
    (``SbomPackageInfo`` or ``SbomPackage``). Returns ``None`` for an empty
    inventory so an empty SBOM is never confused with a changed one.
    """
    tokens: set[str] = set()
    for package in packages:
        name = str(getattr(package, "name", "") or "").strip()
        if not name:
            continue
        version = str(getattr(package, "version", "") or "").strip()
        purl = stable_purl(getattr(package, "purl", None))
        if purl:
            tokens.add(purl)
            continue
        ecosystem = str(getattr(package, "ecosystem", "") or "").strip() or "unknown"
        tokens.add(f"{ecosystem.lower()}:{name.lower()}@{version}")
    if not tokens:
        return None
    payload = "\n".join(sorted(tokens))
    return hashlib.sha256(payload.encode()).hexdigest()


def describe_change(analysis: DependencyPathAnalysis, *, limit: int = 10) -> str:
    """Short human-readable summary used in logs and monitoring rows."""
    if not analysis.dependency_files:
        return "no dependency inputs changed"
    sample = ", ".join(entry.path for entry in analysis.dependency_files[:limit])
    suffix = "" if len(analysis.dependency_files) <= limit else "…"
    return f"{len(analysis.dependency_files)} dependency input(s) changed: {sample}{suffix}"
