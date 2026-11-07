"""Deterministic incident risk scoring.

Five inputs, all evidence-backed:

* worst severity of the attached events,
* asset business criticality (from ``asset_security_profiles``),
* internet exposure,
* threat-intelligence match on any attached indicator,
* evidence volume (a weak, capped bonus — many low-signal events must not
  outrank one critical one).

The output is a score and a priority band. An AI investigation may explain the
incident; it cannot write this score or the priority.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from app.core.enums import IncidentPriority, Severity

SEVERITY_BASE: dict[str, int] = {
    Severity.CRITICAL.value: 85,
    Severity.HIGH.value: 65,
    Severity.MEDIUM.value: 45,
    Severity.LOW.value: 25,
    Severity.INFO.value: 10,
    Severity.UNKNOWN.value: 45,
}

CRITICALITY_BONUS: dict[str, int] = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 0,
}

#: Priority bands are policy, not arithmetic magic: >=85 P1, >=65 P2,
#: >=40 P3, otherwise P4.
PRIORITY_BANDS: tuple[tuple[int, str], ...] = (
    (85, IncidentPriority.P1.value),
    (65, IncidentPriority.P2.value),
    (40, IncidentPriority.P3.value),
)


@dataclass(frozen=True)
class IncidentRisk:
    score: int
    priority: str
    severity: str
    factors: dict[str, int]

    def as_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "priority": self.priority,
            "severity": self.severity,
            "factors": self.factors,
            "policy_version": "incident-risk/1",
        }


def worst_severity(severities: list[str]) -> str:
    order = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 1,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 3,
        Severity.INFO.value: 4,
        Severity.UNKNOWN.value: 5,
    }
    if not severities:
        return Severity.UNKNOWN.value
    return sorted(severities, key=lambda value: order.get(value, 5))[0]


def score(
    *,
    severity: str,
    criticality: str | None = None,
    internet_exposed: bool | None = None,
    threat_matched: bool = False,
    event_count: int = 1,
    rule_priority: str | None = None,
) -> IncidentRisk:
    factors: dict[str, int] = {"severity": SEVERITY_BASE.get(severity, 45)}
    factors["criticality"] = CRITICALITY_BONUS.get((criticality or "").upper(), 0)
    factors["internet_exposure"] = 5 if internet_exposed else 0
    factors["threat_intel"] = 10 if threat_matched else 0
    factors["evidence_volume"] = min(5, int(math.log2(max(0, event_count) + 1)))

    raw = sum(factors.values())
    total = max(0, min(100, raw))

    priority = PRIORITY_BANDS[-1][1]
    for threshold, band in PRIORITY_BANDS:
        if total >= threshold:
            priority = band
            break

    # A rule may demand a higher priority (e.g. container escape is P1). It can
    # never lower the computed one, and a model never supplies it.
    if rule_priority in {item.value for item in IncidentPriority}:
        computed_rank = list(IncidentPriority).index(IncidentPriority(priority))
        rule_rank = list(IncidentPriority).index(IncidentPriority(rule_priority))
        if rule_rank < computed_rank:
            priority = rule_priority

    return IncidentRisk(score=total, priority=priority, severity=severity, factors=factors)
