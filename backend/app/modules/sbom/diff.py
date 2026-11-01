"""Deterministic comparison between two SBOM package inventories.

Identity is the PURL with its version removed, because the whole point is to
detect a version change rather than a new component. When a component has no
PURL the identity falls back to ``ecosystem:name`` and only then to
``name:<name>`` — never to a bare package name, since two ecosystems can ship a
package with the same name.

The engine is pure: it takes two inventories and returns a classification. It
does not read storage, a database or a clock, so the same inputs always produce
the same diff.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from app.core.enums import SbomChangeType
from app.modules.sbom.dependencies import component_identity, purl_identity, stable_purl


@dataclass(frozen=True)
class PackageView:
    """The component fields the diff needs, from any SBOM package source."""

    name: str
    version: str = ""
    ecosystem: str | None = None
    purl: str | None = None
    is_direct: bool | None = None

    @classmethod
    def from_package(cls, package: object) -> PackageView:
        return cls(
            name=str(getattr(package, "name", "") or ""),
            version=str(getattr(package, "version", "") or ""),
            ecosystem=getattr(package, "ecosystem", None),
            purl=getattr(package, "purl", None),
            is_direct=getattr(package, "is_direct", None),
        )


@dataclass(frozen=True)
class ComponentChange:
    change: str
    identity: str
    identity_basis: str
    name: str
    ecosystem: str | None
    purl: str | None
    version_before: str | None
    version_after: str | None
    is_direct_before: bool | None = None
    is_direct_after: bool | None = None

    @property
    def sort_key(self) -> tuple[int, str]:
        order = {
            SbomChangeType.ADDED.value: 0,
            SbomChangeType.REMOVED.value: 1,
            SbomChangeType.VERSION_CHANGED.value: 2,
            SbomChangeType.UNCHANGED.value: 3,
        }
        return order.get(self.change, 9), self.identity


@dataclass
class SbomDiff:
    previous_sbom_id: str | None
    current_sbom_id: str | None
    added: int = 0
    removed: int = 0
    version_changed: int = 0
    unchanged: int = 0
    changes: list[ComponentChange] = field(default_factory=list)

    @property
    def total_previous(self) -> int:
        return self.removed + self.version_changed + self.unchanged

    @property
    def total_current(self) -> int:
        return self.added + self.version_changed + self.unchanged

    @property
    def changed(self) -> int:
        return self.added + self.removed + self.version_changed

    def counts(self) -> dict[str, int]:
        return {
            "added": self.added,
            "removed": self.removed,
            "version_changed": self.version_changed,
            "unchanged": self.unchanged,
            "total_previous": self.total_previous,
            "total_current": self.total_current,
            "changed": self.changed,
        }

    def filter(self, change: str | None) -> list[ComponentChange]:
        if not change:
            return [entry for entry in self.changes if entry.change != SbomChangeType.UNCHANGED.value]
        wanted = change.upper()
        return [entry for entry in self.changes if entry.change == wanted]


@dataclass
class _Group:
    identity: str
    basis: str
    name: str
    ecosystem: str | None
    purl: str | None
    versions: set[str] = field(default_factory=set)
    direct: bool | None = None


def _index(packages: Sequence[object]) -> dict[str, _Group]:
    """Group packages by version-independent identity.

    Duplicate identities can occur in one document (two resolved versions of the
    same purl in a monorepo). They are grouped rather than silently dropped, and
    the version set makes the comparison symmetric.
    """
    groups: dict[str, _Group] = {}
    for raw in packages:
        package = raw if isinstance(raw, PackageView) else PackageView.from_package(raw)
        if not package.name:
            continue
        identity, basis = component_identity(
            name=package.name,
            version=package.version,
            ecosystem=package.ecosystem,
            purl=package.purl,
        )
        group = groups.get(identity)
        if group is None:
            group = _Group(
                identity=identity,
                basis=basis,
                name=package.name,
                ecosystem=package.ecosystem,
                purl=stable_purl(package.purl),
                direct=package.is_direct,
            )
            groups[identity] = group
        elif group.direct is None and package.is_direct is not None:
            group.direct = package.is_direct
        if package.version:
            group.versions.add(package.version)
    return groups


def _version_label(versions: set[str]) -> str | None:
    if not versions:
        return None
    return ", ".join(sorted(versions))


def diff_packages(
    previous: Sequence[object],
    current: Sequence[object],
    *,
    previous_sbom_id: str | None = None,
    current_sbom_id: str | None = None,
) -> SbomDiff:
    """Classify every component into ADDED / REMOVED / VERSION_CHANGED / UNCHANGED."""
    before = _index(previous)
    after = _index(current)
    result = SbomDiff(previous_sbom_id=previous_sbom_id, current_sbom_id=current_sbom_id)

    for identity in sorted(set(before) | set(after)):
        old = before.get(identity)
        new = after.get(identity)
        if old is None and new is not None:
            result.added += 1
            result.changes.append(
                ComponentChange(
                    change=SbomChangeType.ADDED.value,
                    identity=identity,
                    identity_basis=new.basis,
                    name=new.name,
                    ecosystem=new.ecosystem,
                    purl=new.purl,
                    version_before=None,
                    version_after=_version_label(new.versions),
                    is_direct_after=new.direct,
                )
            )
            continue
        if new is None and old is not None:
            result.removed += 1
            result.changes.append(
                ComponentChange(
                    change=SbomChangeType.REMOVED.value,
                    identity=identity,
                    identity_basis=old.basis,
                    name=old.name,
                    ecosystem=old.ecosystem,
                    purl=old.purl,
                    version_before=_version_label(old.versions),
                    version_after=None,
                    is_direct_before=old.direct,
                )
            )
            continue
        assert old is not None and new is not None
        if old.versions != new.versions:
            result.version_changed += 1
            result.changes.append(
                ComponentChange(
                    change=SbomChangeType.VERSION_CHANGED.value,
                    identity=identity,
                    identity_basis=new.basis,
                    name=new.name,
                    ecosystem=new.ecosystem or old.ecosystem,
                    purl=new.purl or old.purl,
                    version_before=_version_label(old.versions),
                    version_after=_version_label(new.versions),
                    is_direct_before=old.direct,
                    is_direct_after=new.direct,
                )
            )
            continue
        result.unchanged += 1
        result.changes.append(
            ComponentChange(
                change=SbomChangeType.UNCHANGED.value,
                identity=identity,
                identity_basis=new.basis,
                name=new.name,
                ecosystem=new.ecosystem or old.ecosystem,
                purl=new.purl or old.purl,
                version_before=_version_label(old.versions),
                version_after=_version_label(new.versions),
                is_direct_before=old.direct,
                is_direct_after=new.direct,
            )
        )

    result.changes.sort(key=lambda entry: entry.sort_key)
    return result


def diff_counts(
    previous: Sequence[object],
    current: Sequence[object],
) -> dict[str, int]:
    """Counts-only diff, for metrics where the full list is not needed."""
    return diff_packages(previous, current).counts()


def identity_of(purl: str | None, name: str, ecosystem: str | None) -> str:
    """Expose the identity rule for callers that need to label a component."""
    return purl_identity(purl) or component_identity(
        name=name, version="", ecosystem=ecosystem, purl=None
    )[0]
