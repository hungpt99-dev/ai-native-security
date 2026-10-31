"""Minimal CVSS v3.0/v3.1 base-score calculation.

Feeds ``cvss_score`` for sources that only publish a vector (OSV does), without
pulling in a heavyweight dependency.
"""

from __future__ import annotations

import math

from app.core.enums import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


class CvssParseError(ValueError):
    pass


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A roundup (smallest 1-decimal >= value)."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000
    return (math.floor(integer / 10000) + 1) / 10


def cvss3_base_score(vector: str) -> float:
    if not vector or not vector.upper().startswith("CVSS:"):
        raise CvssParseError(f"Unsupported CVSS vector: {vector!r}")
    metrics: dict[str, str] = {}
    for chunk in vector.split("/")[1:]:
        if ":" not in chunk:
            continue
        key, value = chunk.split(":", 1)
        metrics[key.upper()] = value.upper()

    try:
        scope_changed = metrics["S"] == "C"
        pr_table = {"N": 0.85, "L": 0.68, "H": 0.5} if scope_changed else {"N": 0.85, "L": 0.62, "H": 0.27}
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = pr_table[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError as exc:
        raise CvssParseError(f"Missing or invalid CVSS metric: {exc}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = (
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    )
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_from_score(score: float | None) -> str:
    if score is None:
        return Severity.UNKNOWN.value
    if score >= 9.0:
        return Severity.CRITICAL.value
    if score >= 7.0:
        return Severity.HIGH.value
    if score >= 4.0:
        return Severity.MEDIUM.value
    if score > 0:
        return Severity.LOW.value
    return Severity.INFO.value
