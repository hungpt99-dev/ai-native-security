"""Policy resolution and defaults.

Policy lives in the database so a change is versioned, reviewable and recorded on
every assessment. The defaults below are the ones shipped by the platform; they
are inserted idempotently at startup so a fresh install behaves predictably
without a manual seed step.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import PolicyKind
from app.core.logging import get_logger
from app.modules.security_policies.models import SecurityPolicy

logger = get_logger(__name__)

DEFAULT_RISK_KEY = "default-risk"
DEFAULT_RISK_VERSION = "1"

DEFAULT_RISK_POLICY: dict[str, Any] = {
    "weights": {
        "cvss": 0.30,
        "kev": 0.18,
        "epss": 0.10,
        "exploit_references": 0.06,
        "directness": 0.10,
        "exposure": 0.12,
        "criticality": 0.10,
        "fix_availability": 0.04,
    },
    "ai_blend": {"deterministic": 0.65, "ai": 0.35},
    "bands": {"critical": 85, "high": 70, "medium": 50, "low": 25},
    "confidence": {
        "ai_weight": 0.6,
        "coverage_weight": 0.4,
        "coverage_bonus": 0.25,
        "review_below": 0.55,
    },
    "gates": {
        "auto_analyze_min_severity": "HIGH",
        "max_findings_per_scan": 10,
        "allow_ai_for_severities": ["CRITICAL", "HIGH", "MEDIUM"],
    },
    #: Neutral value used for a signal whose evidence is missing. Missing data
    #: lowers confidence; it must not silently lower risk.
    "unknown_signal_value": 0.5,
}

DEFAULT_REMEDIATION_POLICY: dict[str, Any] = {
    "require_human_approval": True,
    "allow_patch_proposals": True,
    "max_patch_chars": 12000,
    "allowed_strategies": [
        "DEPENDENCY_UPGRADE",
        "CONFIGURATION_CHANGE",
        "CODE_FIX",
        "COMPONENT_REMOVAL",
        "MITIGATION",
        "NO_ACTION_AVAILABLE",
    ],
}

DEFAULT_DATA_SHARING_POLICY: dict[str, Any] = {
    "send_source_snippets": True,
    "max_snippet_chars": 1200,
    "max_snippets": 5,
    "max_input_chars": 24000,
    "redact_secrets": True,
    "store_prompts": False,
}


def _defaults() -> list[tuple[str, str, str, str, dict[str, Any]]]:
    return [
        (
            DEFAULT_RISK_KEY,
            DEFAULT_RISK_VERSION,
            PolicyKind.RISK_SCORING.value,
            "Default contextual risk policy: CVSS as one signal among several, explicit AI blend.",
            DEFAULT_RISK_POLICY,
        ),
        (
            "default-remediation",
            "1",
            PolicyKind.REMEDIATION.value,
            "Remediation proposals require human approval and never invent versions.",
            DEFAULT_REMEDIATION_POLICY,
        ),
        (
            "default-data-sharing",
            "1",
            PolicyKind.DATA_SHARING.value,
            "What the platform is allowed to send to a model provider.",
            DEFAULT_DATA_SHARING_POLICY,
        ),
    ]


def ensure_defaults(db: Session) -> None:
    """Insert the shipped policies when they are absent (idempotent)."""
    created = 0
    for key, version, kind, description, config in _defaults():
        exists = db.execute(
            select(SecurityPolicy.id).where(SecurityPolicy.key == key, SecurityPolicy.version == version)
        ).scalar_one_or_none()
        if exists:
            continue
        db.add(
            SecurityPolicy(
                key=key,
                version=version,
                kind=kind,
                name=key.replace("-", " ").title(),
                description=description,
                config=config,
                active=True,
                is_default=True,
            )
        )
        created += 1
    if created:
        db.flush()
        logger.info("default security policies created", extra={"extra_fields": {"count": created}})


def active_policy(db: Session, kind: str) -> SecurityPolicy | None:
    return db.execute(
        select(SecurityPolicy)
        .where(SecurityPolicy.kind == kind, SecurityPolicy.active.is_(True))
        .order_by(
            SecurityPolicy.is_default.desc(), SecurityPolicy.priority.asc(), SecurityPolicy.created_at.desc()
        )
        .limit(1)
    ).scalar_one_or_none()


def risk_policy(db: Session) -> tuple[dict[str, Any], str, str]:
    """Return (config, key, version) for the active risk policy."""
    row = active_policy(db, PolicyKind.RISK_SCORING.value)
    if row is None:
        return DEFAULT_RISK_POLICY, DEFAULT_RISK_KEY, DEFAULT_RISK_VERSION
    merged = {**DEFAULT_RISK_POLICY, **(row.config or {})}
    return merged, row.key, row.version


def list_policies(db: Session, *, kind: str | None = None) -> list[SecurityPolicy]:
    stmt = select(SecurityPolicy).order_by(
        SecurityPolicy.kind, SecurityPolicy.key, SecurityPolicy.created_at.desc()
    )
    if kind:
        stmt = stmt.where(SecurityPolicy.kind == kind.upper())
    return list(db.execute(stmt).scalars())
