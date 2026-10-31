"""Deterministic version comparison and range evaluation.

Version maths decides whether a finding is still exploitable and whether a
proposed fixed version actually leaves the affected range. That decision is
never delegated to a model: this module is the single source of truth.

Two comparison families are implemented because the ecosystems genuinely differ:

* **dpkg-ish** (`Debian`, `RPM`, `Alpine`, `Arch Linux`, `SUSE`): epoch,
  upstream version, revision, with `~` sorting before everything.
* **generic semver/PEP 440 hybrid** (everything else): release numbers,
  pre-release labels (`dev` < `alpha` < `beta` < `pre` < `rc` < release),
  post/rev/patch releases above the release.

Unparseable input never raises into the caller's happy path: helpers return
``None`` (= "unknown"), which every caller must treat as missing evidence.
"""

from __future__ import annotations

import re
from typing import Any

DEBIAN_ECOSYSTEMS = frozenset({"debian", "rpm", "alpine", "arch linux", "red hat", "suse"})

_PRERELEASE_RANK = {
    "dev": 0,
    "snapshot": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "pre": 3,
    "preview": 3,
    "milestone": 3,
    "m": 3,
    "rc": 4,
}
_POST_RANK = {"post": 1, "rev": 1, "r": 1, "patch": 1, "final": 1}

_RELEASE_RE = re.compile(r"^(\d+(?:[._]\d+)*)")
_SUFFIX_RE = re.compile(r"^([a-z]+)\.?(\d*)")
_EPOCH_RE = re.compile(r"^(\d+):")
_CONSTRAINT_RE = re.compile(r"^\s*(>=|<=|==|>|<|=)\s*([0-9][^\s]*|[vV][^\s]*)\s*$")


class UncomparableVersion(ValueError):
    """Raised internally when a version string cannot be interpreted."""


# --------------------------------------------------------------------------- dpkg


def _dpkg_order(char: str) -> int:
    if char == "~":
        return -1
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_dpkg_part(left: str, right: str) -> int:
    """Compare upstream/revision strings the way dpkg does."""
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            lc = _dpkg_order(left[i]) if i < len(left) else 0
            rc = _dpkg_order(right[j]) if j < len(right) else 0
            if lc != rc:
                return -1 if lc < rc else 1
            i += 1
            j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        start_left, start_right = i, j
        while i < len(left) and left[i].isdigit():
            i += 1
        while j < len(right) and right[j].isdigit():
            j += 1
        left_run = left[start_left:i]
        right_run = right[start_right:j]
        if len(left_run) != len(right_run):
            return -1 if len(left_run) < len(right_run) else 1
        if left_run != right_run:
            return -1 if left_run < right_run else 1
    return 0


def _split_debian(version: str) -> tuple[int, str, str]:
    value = version.strip().lower()
    if not value:
        raise UncomparableVersion("empty version")
    epoch = 0
    match = _EPOCH_RE.match(value)
    if match:
        epoch = int(match.group(1))
        value = value[match.end() :]
    if not value:
        raise UncomparableVersion(version)
    if "-" in value:
        upstream, revision = value.rsplit("-", 1)
    else:
        upstream, revision = value, ""
    return epoch, upstream, revision


def _compare_debian(left: str, right: str) -> int:
    le, lu, lr = _split_debian(left)
    re_, ru, rr = _split_debian(right)
    if le != re_:
        return -1 if le < re_ else 1
    result = _compare_dpkg_part(lu, ru)
    if result:
        return result
    return _compare_dpkg_part(lr, rr)


# ------------------------------------------------------------------------ generic


def _generic_key(version: str) -> tuple[int, tuple[int, ...], tuple[int, int, int, str], int]:
    value = (version or "").strip().lower()
    if not value:
        raise UncomparableVersion("empty version")
    if value.startswith("v"):
        value = value[1:]
    if "+" in value:  # build metadata never affects ordering
        value = value.split("+", 1)[0]
    epoch = 0
    match = _EPOCH_RE.match(value)
    if match:
        epoch = int(match.group(1))
        value = value[match.end() :]
    release_match = _RELEASE_RE.match(value)
    if not release_match:
        raise UncomparableVersion(version)
    release_raw = release_match.group(1)
    release = [int(part) for part in re.split(r"[._]", release_raw)]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    rest = value[release_match.end() :].strip(".-_ ")
    # release marker sorts above every pre-release
    prerelease: tuple[int, int, int, str] = (1, 0, 0, "")
    post = 0
    if rest:
        suffix = _SUFFIX_RE.match(rest)
        if suffix:
            label = suffix.group(1)
            digits = suffix.group(2)
            number = int(digits) if digits else 0
            if label in _PRERELEASE_RANK:
                prerelease = (0, _PRERELEASE_RANK[label], number, "")
                rest = rest[suffix.end() :].strip(".-_ ")
                if rest:
                    # e.g. "rc1.post2" — post release of a pre-release
                    second = _SUFFIX_RE.match(rest)
                    if second and second.group(1) in _POST_RANK:
                        post = int(second.group(2) or 0)
                    else:
                        prerelease = (*prerelease[:3], rest)
            elif label in _POST_RANK:
                post = number
            else:
                prerelease = (0, 5, number, label)
        elif rest.isdigit():
            post = int(rest)
        else:
            prerelease = (0, 5, 0, rest)
    return epoch, tuple(release), prerelease, post


def _compare_generic(left: str, right: str) -> int:
    lk = _generic_key(left)
    rk = _generic_key(right)
    if lk == rk:
        return 0
    return -1 if lk < rk else 1


# ------------------------------------------------------------------------- public


def is_debian_family(ecosystem: str | None) -> bool:
    if not ecosystem:
        return False
    return ecosystem.strip().lower() in DEBIAN_ECOSYSTEMS


def compare_versions(left: str, right: str, ecosystem: str | None = None) -> int:
    """Return -1/0/1. Raises ``UncomparableVersion`` on unparseable input."""
    if left == right:
        return 0
    if is_debian_family(ecosystem):
        return _compare_debian(left, right)
    return _compare_generic(left, right)


def safe_compare(left: str | None, right: str | None, ecosystem: str | None = None) -> int | None:
    """Comparison that answers ``None`` instead of raising."""
    if not left or not right:
        return None
    try:
        return compare_versions(left, right, ecosystem)
    except UncomparableVersion:
        return None


def version_in_range(
    version: str | None, *, introduced: str | None, fixed: str | None, ecosystem: str | None = None
) -> bool | None:
    """Half-open ``[introduced, fixed)`` membership. ``None`` = unknown."""
    if not version:
        return None
    if introduced and introduced not in {"0", "*"}:
        cmp_introduced = safe_compare(version, introduced, ecosystem)
        if cmp_introduced is None:
            return None
        if cmp_introduced < 0:
            return False
    if fixed:
        cmp_fixed = safe_compare(version, fixed, ecosystem)
        if cmp_fixed is None:
            return None
        return cmp_fixed < 0
    return True


def parse_constraint(expression: str) -> list[tuple[str, str]]:
    """Parse ``">=1.2.0 <2.0.0"`` / ``">= 1.2, < 2"`` into (operator, version)."""
    parts = [part for part in re.split(r"[,\s]+", (expression or "").strip()) if part]
    constraints: list[tuple[str, str]] = []
    index = 0
    while index < len(parts):
        token = parts[index]
        match = _CONSTRAINT_RE.match(token)
        if match:
            constraints.append((match.group(1), match.group(2)))
            index += 1
            continue
        if index + 1 < len(parts) and _CONSTRAINT_RE.match(f"{token}{parts[index + 1]}"):
            joined = _CONSTRAINT_RE.match(f"{token}{parts[index + 1]}")
            assert joined is not None
            constraints.append((joined.group(1), joined.group(2)))
            index += 2
            continue
        index += 1
    return constraints


def satisfies_constraints(
    version: str, constraints: list[tuple[str, str]], ecosystem: str | None
) -> bool | None:
    if not version or not constraints:
        return None
    unknown = False
    for operator, target in constraints:
        cmp_value = safe_compare(version, target, ecosystem)
        if cmp_value is None:
            unknown = True
            continue
        if operator in {">="} and cmp_value < 0:
            return False
        if operator in {">"} and cmp_value <= 0:
            return False
        if operator in {"<="} and cmp_value > 0:
            return False
        if operator in {"<"} and cmp_value >= 0:
            return False
        if operator in {"=", "=="} and cmp_value != 0:
            return False
    return None if unknown else True


def is_affected(
    version: str | None,
    ranges: list[Any] | None,
    ecosystem: str | None = None,
) -> bool | None:
    """Evaluate OSV-style range data for one version.

    Returns ``True`` (affected by at least one range), ``False`` (evaluated and
    not affected), or ``None`` (no usable range data — must be reported as
    missing information, never as "safe").
    """
    if not version or not ranges:
        return None
    evaluated = False
    for entry in ranges:
        if isinstance(entry, str):
            constraints = parse_constraint(entry)
            result = satisfies_constraints(version, constraints, ecosystem)
            if result is None:
                continue
            evaluated = True
            if result:
                return True
            continue
        if not isinstance(entry, dict):
            continue
        events = entry.get("events") or []
        if not isinstance(events, list) or not events:
            continue
        affected = False
        usable = True
        for event in events:
            if not isinstance(event, dict):
                usable = False
                continue
            if "introduced" in event:
                introduced = str(event["introduced"])
                if introduced in {"0", "*"}:
                    affected = True
                    continue
                cmp_value = safe_compare(version, introduced, ecosystem)
                if cmp_value is None:
                    usable = False
                    continue
                affected = cmp_value >= 0
            elif "fixed" in event:
                cmp_value = safe_compare(version, str(event["fixed"]), ecosystem)
                if cmp_value is None:
                    usable = False
                    continue
                if cmp_value >= 0:
                    affected = False
            elif "last_affected" in event:
                cmp_value = safe_compare(version, str(event["last_affected"]), ecosystem)
                if cmp_value is None:
                    usable = False
                    continue
                if cmp_value > 0:
                    affected = False
            elif "limit" in event:
                cmp_value = safe_compare(version, str(event["limit"]), ecosystem)
                if cmp_value is None:
                    usable = False
                    continue
                if cmp_value >= 0:
                    affected = False
        if not usable:
            continue
        evaluated = True
        if affected:
            return True
    return False if evaluated else None


def minimum_fixed_version(fixed_versions: list[str] | None, ecosystem: str | None = None) -> str | None:
    """Lowest semantically-valid fixed version, or ``None``."""
    candidates = [value for value in (fixed_versions or []) if value]
    if not candidates:
        return None
    best = candidates[0]
    for candidate in candidates[1:]:
        cmp_value = safe_compare(candidate, best, ecosystem)
        if cmp_value is None:
            continue
        if cmp_value < 0:
            best = candidate
    return best


def is_fixed_version_valid(
    candidate: str | None,
    *,
    fixed_versions: list[str] | None,
    current_version: str | None,
    ecosystem: str | None = None,
) -> bool | None:
    """A remediation target is valid only if authoritative data supports it.

    ``True`` when ``candidate`` is at or above a known fixed version and above
    the current one; ``None`` when the comparison cannot be made.
    """
    if not candidate:
        return None
    minimum = minimum_fixed_version(fixed_versions, ecosystem)
    if minimum is None:
        return None
    against_fixed = safe_compare(candidate, minimum, ecosystem)
    if against_fixed is None:
        return None
    if against_fixed < 0:
        return False
    if current_version:
        against_current = safe_compare(candidate, current_version, ecosystem)
        if against_current is not None and against_current <= 0:
            return False
    return True


def explain_comparison(left: str, right: str, ecosystem: str | None = None) -> str:
    """Human-readable comparison, used in verification evidence."""
    result = safe_compare(left, right, ecosystem)
    if result is None:
        return f"{left} vs {right}: unknown (uncomparable)"
    symbol = "==" if result == 0 else ("<" if result < 0 else ">")
    return f"{left} {symbol} {right}"
