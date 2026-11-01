"""Deterministic SBOM diff engine."""

from __future__ import annotations

from app.modules.sbom.diff import PackageView, diff_counts, diff_packages, identity_of


def _pkg(name: str, version: str, *, ecosystem: str = "PyPI", purl: str | None = None,
         is_direct: bool | None = None) -> PackageView:
    return PackageView(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=purl or f"pkg:{ecosystem.lower()}/{name}@{version}",
        is_direct=is_direct,
    )


def test_identical_inventories_have_no_changes() -> None:
    before = [_pkg("requests", "2.31.0"), _pkg("flask", "3.0.0")]
    after = [_pkg("requests", "2.31.0"), _pkg("flask", "3.0.0")]
    diff = diff_packages(before, after)
    assert (diff.added, diff.removed, diff.version_changed, diff.unchanged) == (0, 0, 0, 2)
    assert diff.changed == 0
    assert diff.filter(None) == []
    assert len(diff.filter("UNCHANGED")) == 2


def test_added_dependency() -> None:
    diff = diff_packages([_pkg("requests", "2.31.0")], [
        _pkg("requests", "2.31.0"),
        _pkg("httpx", "0.27.0"),
    ])
    assert diff.added == 1
    added = diff.filter("ADDED")[0]
    assert added.name == "httpx"
    assert added.version_before is None
    assert added.version_after == "0.27.0"


def test_removed_dependency() -> None:
    diff = diff_packages(
        [_pkg("requests", "2.31.0"), _pkg("urllib3", "1.26.0")],
        [_pkg("requests", "2.31.0")],
    )
    assert diff.removed == 1
    removed = diff.filter("REMOVED")[0]
    assert removed.name == "urllib3"
    assert removed.version_before == "1.26.0"
    assert removed.version_after is None


def test_dependency_upgrade_is_a_version_change_not_add_remove() -> None:
    diff = diff_packages(
        [_pkg("flask", "3.0.0", is_direct=True)],
        [_pkg("flask", "3.0.3", is_direct=True)],
    )
    assert (diff.added, diff.removed, diff.version_changed) == (0, 0, 1)
    change = diff.filter("VERSION_CHANGED")[0]
    assert change.version_before == "3.0.0"
    assert change.version_after == "3.0.3"
    assert change.is_direct_before is True and change.is_direct_after is True


def test_same_package_name_in_two_ecosystems_is_not_merged() -> None:
    python = PackageView(name="requests", version="2.31.0", ecosystem="PyPI",
                         purl="pkg:pypi/requests@2.31.0")
    node = PackageView(name="requests", version="9.9.9", ecosystem="npm",
                       purl="pkg:npm/requests@9.9.9")
    diff = diff_packages([python], [node])
    assert diff.added == 1 and diff.removed == 1
    assert diff.version_changed == 0
    assert {entry.identity for entry in diff.filter("ADDED")} == {"pkg:npm/requests"}


def test_identity_falls_back_when_purl_is_missing() -> None:
    diff = diff_packages(
        [PackageView(name="legacy", version="1.0", ecosystem="PyPI", purl=None)],
        [PackageView(name="legacy", version="1.1", ecosystem="PyPI", purl=None)],
    )
    assert diff.version_changed == 1
    change = diff.filter("VERSION_CHANGED")[0]
    assert change.identity == "pypi:legacy"
    assert change.identity_basis == "ecosystem_name"


def test_qualifiers_do_not_create_a_false_change() -> None:
    diff = diff_packages(
        [PackageView(name="openssl", version="3.0.12", ecosystem="Debian",
                     purl="pkg:deb/debian/openssl@3.0.12?arch=amd64")],
        [PackageView(name="openssl", version="3.0.12", ecosystem="Debian",
                     purl="pkg:deb/debian/openssl@3.0.12?arch=arm64")],
    )
    assert diff.unchanged == 1
    assert diff.changed == 0


def test_two_versions_of_one_component_are_grouped() -> None:
    diff = diff_packages(
        [
            PackageView(name="grpc", version="1.0", ecosystem="Maven",
                        purl="pkg:maven/io.grpc/grpc@1.0"),
            PackageView(name="grpc", version="2.0", ecosystem="Maven",
                        purl="pkg:maven/io.grpc/grpc@2.0"),
        ],
        [
            PackageView(name="grpc", version="1.0", ecosystem="Maven",
                        purl="pkg:maven/io.grpc/grpc@1.0"),
        ],
    )
    assert diff.unchanged == 0
    assert diff.version_changed == 1
    change = diff.filter("VERSION_CHANGED")[0]
    assert change.version_before == "1.0, 2.0"
    assert change.version_after == "1.0"


def test_counts_helper_and_identity_exposure() -> None:
    counts = diff_counts([_pkg("a", "1")], [_pkg("a", "2"), _pkg("b", "1")])
    assert counts["added"] == 1
    assert counts["version_changed"] == 1
    assert counts["removed"] == 0
    assert counts["total_current"] == 2
    assert identity_of("pkg:pypi/a@1.0", "a", "PyPI") == "pkg:pypi/a"
