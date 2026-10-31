"""Deterministic risk signals.

Every number here is reproducible from stored data plus the policy document. The
model never computes these; it reasons on top of them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.enums import Severity
from app.modules.security_intelligence.schemas import SecurityContext

CRITICALITY_VALUES = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.55,
    "LOW": 0.3,
}
EXPOSURE_VALUES = {True: 1.0, False: 0.25}
FIX_AVAILABLE_VALUES = {"available": 0.35, "unavailable": 1.0}

#: Reference hosts that usually mean "there is an exploit or a PoC".
EXPLOIT_HINTS = (
    "exploit-db.com",
    "packetstormsecurity",
    "metasploit",
    "github.com",
    "poc",
    "exploit",
)

SEVERITY_FALLBACK = {
    Severity.CRITICAL.value: 9.5,
    Severity.HIGH.value: 8.0,
    Severity.MEDIUM.value: 5.5,
    Severity.LOW.value: 3.0,
    Severity.INFO.value: 0.5,
}


@dataclass
class Signal:
    key: str
    label: str
    value: Any
    normalized: float
    weight: float
    known: bool
    source: str
    note: str = ""

    @property
    def contribution(self) -> float:
        return round(self.normalized * self.weight, 4)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "normalized": round(self.normalized, 4),
            "weight": self.weight,
            "contribution": self.contribution,
            "known": self.known,
            "source": self.source,
            "note": self.note,
        }


@dataclass
class SignalSet:
    signals: list[Signal] = field(default_factory=list)
    score: int = 0
    coverage: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "coverage": round(self.coverage, 3),
            "signals": [signal.as_dict() for signal in self.signals],
        }

    def by_key(self, key: str) -> Signal | None:
        return next((signal for signal in self.signals if signal.key == key), None)


def _exploit_reference_score(references: list[dict[str, Any]]) -> tuple[float, bool, str]:
    if not references:
        return 0.0, False, "no references stored"
    matches = [
        str(reference.get("url") or "")
        for reference in references
        if any(hint in str(reference.get("url") or "").lower() for hint in EXPLOIT_HINTS)
    ]
    if matches:
        return 1.0, True, f"{len(matches)} reference(s) point at exploit/PoC sources"
    return 0.0, True, "references exist but none points at a known exploit source"


def compute_signals(context: SecurityContext, policy: dict[str, Any]) -> SignalSet:
    weights = {**DEFAULT_WEIGHTS, **(policy.get("weights") or {})}
    unknown_value = float(policy.get("unknown_signal_value", 0.5))
    vulnerability = context.vulnerability or {}
    business = context.business or {}
    dependency = context.dependency or {}
    finding = context.finding or {}

    signals: list[Signal] = []

    # ---- CVSS ------------------------------------------------------------
    cvss = vulnerability.get("cvss_score")
    if cvss is None:
        cvss = finding.get("cvss_score")
    if cvss is None:
        severity_score = SEVERITY_FALLBACK.get(str(finding.get("severity") or "").upper())
        cvss_known = False
        note = "CVSS not stored; platform severity used as a coarse proxy"
        normalized_cvss = (severity_score or 5.0) / 10.0
        value: Any = severity_score
    else:
        cvss_known = True
        note = ""
        normalized_cvss = min(float(cvss), 10.0) / 10.0
        value = float(cvss)
    signals.append(
        Signal(
            "cvss",
            "CVSS score",
            value,
            normalized_cvss,
            weights["cvss"],
            cvss_known,
            "vulnerability_intel",
            note,
        )
    )

    # ---- CISA KEV --------------------------------------------------------
    is_kev = vulnerability.get("is_kev")
    signals.append(
        Signal(
            "kev",
            "CISA KEV listed",
            is_kev,
            1.0 if is_kev else (unknown_value if is_kev is None else 0.0),
            weights["kev"],
            is_kev is not None,
            "cisa_kev",
            "known to be exploited in the wild" if is_kev else "",
        )
    )

    # ---- EPSS ------------------------------------------------------------
    epss_score = vulnerability.get("epss_score")
    signals.append(
        Signal(
            "epss",
            "EPSS probability",
            epss_score,
            float(epss_score) if epss_score is not None else unknown_value,
            weights["epss"],
            epss_score is not None,
            "first_epss",
        )
    )

    # ---- exploit references ---------------------------------------------
    exploit_value, exploit_known, exploit_note = _exploit_reference_score(
        vulnerability.get("references") or []
    )
    signals.append(
        Signal(
            "exploit_references",
            "Exploit / PoC references",
            len(vulnerability.get("references") or []),
            exploit_value if exploit_known else unknown_value,
            weights["exploit_references"],
            exploit_known,
            "vulnerability_references",
            exploit_note,
        )
    )

    # ---- dependency directness ------------------------------------------
    is_direct = dependency.get("is_direct")
    if is_direct is True:
        directness_value, directness_known = 1.0, True
    elif is_direct is False:
        directness_value, directness_known = 0.75, True
    else:
        directness_value, directness_known = unknown_value, False
    signals.append(
        Signal(
            "directness",
            "Dependency directness",
            is_direct,
            directness_value,
            weights["directness"],
            directness_known,
            "sbom_graph",
        )
    )

    # ---- exposure --------------------------------------------------------
    exposed = business.get("internet_exposed")
    signals.append(
        Signal(
            "exposure",
            "Internet exposure",
            exposed,
            EXPOSURE_VALUES.get(exposed, unknown_value) if exposed is not None else unknown_value,
            weights["exposure"],
            exposed is not None,
            "asset_security_profile",
        )
    )

    # ---- criticality -----------------------------------------------------
    criticality = business.get("criticality")
    signals.append(
        Signal(
            "criticality",
            "Asset criticality",
            criticality,
            CRITICALITY_VALUES.get(str(criticality or "").upper(), unknown_value)
            if criticality
            else unknown_value,
            weights["criticality"],
            bool(criticality),
            "asset_security_profile",
        )
    )

    # ---- fix availability (no fix = more urgent) -------------------------
    fixed_versions = vulnerability.get("fixed_versions") or []
    fix_known = vulnerability.get("available") is True
    fix_value = FIX_AVAILABLE_VALUES["available"] if fixed_versions else FIX_AVAILABLE_VALUES["unavailable"]
    signals.append(
        Signal(
            "fix_availability",
            "Fix availability",
            bool(fixed_versions),
            fix_value if fix_known else unknown_value,
            weights["fix_availability"],
            fix_known,
            "vulnerability_intel",
            "" if fixed_versions else "no fixed version known",
        )
    )

    total_weight = sum(signal.weight for signal in signals) or 1.0
    weighted = sum(signal.normalized * signal.weight for signal in signals)
    known_weight = sum(signal.weight for signal in signals if signal.known)
    score = int(round(min(100.0, max(0.0, weighted / total_weight * 100))))
    coverage = round(known_weight / total_weight, 4)
    return SignalSet(signals=signals, score=score, coverage=coverage)


DEFAULT_WEIGHTS = {
    "cvss": 0.30,
    "kev": 0.18,
    "epss": 0.10,
    "exploit_references": 0.06,
    "directness": 0.10,
    "exposure": 0.12,
    "criticality": 0.10,
    "fix_availability": 0.04,
}
