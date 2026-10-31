"""Dependency relationship analysis over stored SBOM graphs.

Answers the questions that separate "a CVE exists" from "this application is
affected": is the vulnerable package direct or transitive, what pulls it in, and
how far is it from a declared dependency.
"""

from __future__ import annotations

import uuid
from collections import deque
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.modules.sbom.models import Sbom, SbomPackage, SbomPackageEdge

logger = get_logger(__name__)

MAX_DEPTH = 8
MAX_PARENTS = 10


def latest_sbom_id(db: Session, asset_id: uuid.UUID) -> uuid.UUID | None:
    return db.execute(
        select(Sbom.id).where(Sbom.asset_id == asset_id).order_by(Sbom.created_at.desc()).limit(1)
    ).scalar_one_or_none()


def analyze_package(
    db: Session,
    *,
    asset_id: uuid.UUID,
    package_name: str,
    package_version: str | None = None,
    sbom_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Return dependency context for one package, or an explicit "unknown".

    The result always carries ``available`` so callers can report missing
    evidence instead of assuming "transitive" or "not used".
    """
    resolved_sbom_id = sbom_id or latest_sbom_id(db, asset_id)
    if resolved_sbom_id is None:
        return {"available": False, "reason": "no_sbom_for_asset"}

    packages = (
        db.execute(
            select(SbomPackage).where(
                SbomPackage.sbom_id == resolved_sbom_id, SbomPackage.name == package_name
            )
        )
        .scalars()
        .all()
    )
    if not packages:
        return {
            "available": False,
            "reason": "package_not_in_latest_sbom",
            "sbom_id": str(resolved_sbom_id),
            "package_name": package_name,
        }
    package = None
    if package_version:
        package = next((row for row in packages if row.version == package_version), None)
    package = package or packages[0]

    edges = (
        db.execute(select(SbomPackageEdge).where(SbomPackageEdge.sbom_id == resolved_sbom_id)).scalars().all()
    )

    parents: dict[str, list[dict[str, Any]]] = {}
    children: dict[str, list[str]] = {}
    for edge in edges:
        if edge.to_name:
            parents.setdefault(edge.to_name, []).append(
                {
                    "name": edge.from_name,
                    "version": edge.from_version,
                    "ref": edge.from_ref,
                    "root": edge.from_ref is None,
                }
            )
        if edge.from_name:
            children.setdefault(edge.from_name, []).append(edge.to_name or "")

    if not edges:
        # Generator gave no graph: report unknown, but still surface the
        # generator's own direct flag when it exists.
        return {
            "available": False,
            "reason": "dependency_graph_unavailable",
            "sbom_id": str(resolved_sbom_id),
            "package_name": package.name,
            "installed_version": package.version,
            "ecosystem": package.ecosystem,
            "purl": package.purl,
            "is_direct": package.is_direct,
            "parents": [],
            "depth": None,
        }

    direct_names = {edge.to_name for edge in edges if edge.from_ref is None and edge.to_name}
    is_direct = package.is_direct
    if is_direct is None:
        is_direct = package.name in direct_names

    depth = _depth_from_root(package.name, parents)
    root_parents = [parent for parent in parents.get(package.name, []) if parent.get("root")]
    return {
        "available": True,
        "reason": None,
        "sbom_id": str(resolved_sbom_id),
        "package_name": package.name,
        "installed_version": package.version,
        "ecosystem": package.ecosystem,
        "purl": package.purl,
        "is_direct": is_direct,
        "depth": depth,
        "parents": parents.get(package.name, [])[:MAX_PARENTS],
        "direct_entry_points": sorted({parent["name"] for parent in root_parents if parent["name"]})[
            :MAX_PARENTS
        ],
        "child_count": len(children.get(package.name, [])),
        "edge_count": len(edges),
    }


def _depth_from_root(name: str, parents: dict[str, list[dict[str, Any]]]) -> int | None:
    """Breadth-first distance from a root dependency (root = depth 1)."""
    direct = any(parent.get("root") for parent in parents.get(name, []))
    if direct:
        return 1
    seen = {name}
    queue: deque[tuple[str, int]] = deque([(name, 0)])
    while queue:
        current, distance = queue.popleft()
        if distance >= MAX_DEPTH:
            continue
        for parent in parents.get(current, []):
            parent_name = parent.get("name")
            if not parent_name or parent_name in seen:
                continue
            if parent.get("root"):
                return distance + 2
            seen.add(parent_name)
            queue.append((parent_name, distance + 1))
    return None


def dependency_summary(
    db: Session, *, asset_id: uuid.UUID, sbom_id: uuid.UUID | None = None
) -> dict[str, Any]:
    """Cheap aggregate used by the dashboard and the assistant."""
    resolved = sbom_id or latest_sbom_id(db, asset_id)
    if resolved is None:
        return {"available": False, "direct": 0, "transitive": 0, "edges": 0}
    rows = db.execute(select(SbomPackage.is_direct).where(SbomPackage.sbom_id == resolved)).scalars().all()
    edge_count = (
        db.execute(select(SbomPackageEdge.id).where(SbomPackageEdge.sbom_id == resolved)).scalars().all()
    )
    direct = sum(1 for flag in rows if flag is True)
    transitive = sum(1 for flag in rows if flag is False)
    return {
        "available": bool(edge_count),
        "sbom_id": str(resolved),
        "direct": direct,
        "transitive": transitive,
        "unknown": len(rows) - direct - transitive,
        "edges": len(edge_count),
    }
