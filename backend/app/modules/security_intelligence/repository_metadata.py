"""Deterministic repository facts derived from an SBOM (and the workspace).

Nothing here calls a model. The output is what allows the platform to answer
"what is this repository written in" without asking an LLM to guess from a name.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.modules.scanners.syft import SbomPackageInfo
from app.modules.security_intelligence.models import AssetRepositoryMetadata

logger = get_logger(__name__)

#: OSV ecosystem -> primary language. One package manager can imply several
#: languages (npm ships TypeScript), so the value is the dominant one.
ECOSYSTEM_LANGUAGES: dict[str, str] = {
    "npm": "JavaScript/TypeScript",
    "PyPI": "Python",
    "Go": "Go",
    "Maven": "Java",
    "RubyGems": "Ruby",
    "crates.io": "Rust",
    "NuGet": "C#",
    "Packagist": "PHP",
    "composer": "PHP",
    "SwiftURL": "Swift",
    "Pub": "Dart",
    "Hex": "Elixir",
    "Debian": "C/C++ (system packages)",
    "RPM": "C/C++ (system packages)",
    "Alpine": "C/C++ (system packages)",
    "GitHub Actions": "CI configuration",
}

#: Frameworks detected by exact package name; deliberately small and conservative
#: — a false negative is a missing hint, a false positive is misinformation.
FRAMEWORK_PACKAGES: dict[str, str] = {
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "torch": "PyTorch",
    "tensorflow": "TensorFlow",
    "pydantic": "Pydantic",
    "sqlalchemy": "SQLAlchemy",
    "celery": "Celery",
    "express": "Express",
    "koa": "Koa",
    "fastify": "Fastify",
    "react": "React",
    "react-dom": "React",
    "next": "Next.js",
    "vue": "Vue",
    "nuxt": "Nuxt",
    "@angular/core": "Angular",
    "svelte": "Svelte",
    "tailwindcss": "Tailwind CSS",
    "spring-boot": "Spring Boot",
    "spring-core": "Spring",
    "rails": "Ruby on Rails",
    "sinatra": "Sinatra",
    "laravel/framework": "Laravel",
    "symfony/framework-bundle": "Symfony",
    "gin": "Gin",
    "echo": "Echo",
    "actix-web": "Actix Web",
    "axum": "Axum",
    "log4j-core": "Log4j",
    "struts2-core": "Apache Struts",
    "shiro-core": "Apache Shiro",
    "jackson-databind": "Jackson",
}

#: Manifest filenames worth reporting; we only list files that actually exist.
MANIFEST_FILES = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "packages.config",
    "Directory.Build.props",
    "pubspec.yaml",
    "Package.swift",
    "Dockerfile",
    "docker-compose.yml",
)


def detect_frameworks(packages: list[SbomPackageInfo]) -> list[str]:
    found: set[str] = set()
    for package in packages:
        name = package.name.lower()
        framework = FRAMEWORK_PACKAGES.get(name)
        if framework:
            found.add(framework)
            continue
        # Maven artifacts are often "org.springframework:spring-web"; the group
        # prefix is a reliable hint for a small set of families.
        for prefix, label in (
            ("spring-boot", "Spring Boot"),
            ("springframework", "Spring"),
            ("org.apache.struts", "Apache Struts"),
        ):
            if prefix in name:
                found.add(label)
    return sorted(found)


def language_breakdown(packages: list[SbomPackageInfo]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for package in packages:
        ecosystem = package.ecosystem
        if not ecosystem:
            continue
        language = ECOSYSTEM_LANGUAGES.get(ecosystem)
        if language:
            counter[language] += 1
    total = sum(counter.values()) or 1
    return [
        {"language": language, "packages": count, "share": round(count / total, 3)}
        for language, count in counter.most_common(10)
    ]


def detect_manifests(workspace: Path | None) -> list[str]:
    if workspace is None or not workspace.exists():
        return []
    settings = get_settings()
    found: list[str] = []
    examined = 0
    for path in workspace.rglob("*"):
        if examined >= settings.max_snippet_files * 50:
            break
        if not path.is_file():
            continue
        examined += 1
        if path.name in MANIFEST_FILES:
            try:
                found.append(str(path.relative_to(workspace)))
            except ValueError:  # pragma: no cover - defensive
                continue
        if len(found) >= 50:
            break
    return sorted(set(found))


def collect(
    db: Session,
    *,
    asset_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    packages: list[SbomPackageInfo],
    workspace: Path | None,
    default_branch: str | None = None,
) -> AssetRepositoryMetadata:
    """Upsert repository metadata for an asset (one row per asset)."""
    row = db.get(AssetRepositoryMetadata, asset_id)
    if row is None:
        row = AssetRepositoryMetadata(asset_id=asset_id)
        db.add(row)
    row.scan_id = scan_id
    row.default_branch = default_branch
    row.languages = language_breakdown(packages)
    row.frameworks = detect_frameworks(packages)
    row.manifests = detect_manifests(workspace)
    row.collected_at = datetime.now(UTC)
    db.flush()
    logger.info(
        "repository metadata collected",
        extra={
            "extra_fields": {
                "asset_id": str(asset_id),
                "languages": [entry["language"] for entry in row.languages],
                "frameworks": row.frameworks,
                "manifests": len(row.manifests),
            }
        },
    )
    return row


def get(db: Session, asset_id: uuid.UUID) -> AssetRepositoryMetadata | None:
    return db.get(AssetRepositoryMetadata, asset_id)


def as_context(row: AssetRepositoryMetadata | None) -> dict[str, Any]:
    if row is None:
        return {"collected": False}
    return {
        "collected": True,
        "languages": row.languages or [],
        "frameworks": row.frameworks or [],
        "manifests": row.manifests or [],
        "default_branch": row.default_branch,
        "collected_at": row.collected_at.isoformat() if row.collected_at else None,
    }


def load_for_assets(db: Session, asset_ids: list[uuid.UUID]) -> dict[uuid.UUID, AssetRepositoryMetadata]:
    if not asset_ids:
        return {}
    rows = (
        db.execute(select(AssetRepositoryMetadata).where(AssetRepositoryMetadata.asset_id.in_(asset_ids)))
        .scalars()
        .all()
    )
    return {row.asset_id: row for row in rows}
