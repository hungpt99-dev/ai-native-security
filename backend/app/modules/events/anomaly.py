"""Deterministic anomaly detection over stored events.

The baseline is arithmetic, not a model: for every (asset, event_type) pair the
job compares the last 24 hours with the mean daily rate of the preceding
``ANS_EVENTS_ANOMALY_BASELINE_DAYS`` days. A pair needs a minimum absolute count
before it can be called anomalous, so a quiet repository does not produce an
alert from a single event.

Cold start is explicit: when there is no history at all the threshold is raised
(``min_count * 2.5``), and the resulting event records ``baseline_days: 0`` so an
analyst can see the baseline was not established.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import DetectionRuleType, EventCategory, EventSource, Severity
from app.core.logging import get_logger
from app.modules.events import rules as rule_engine
from app.modules.events.models import DetectionRule, SecurityEvent

logger = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def _anomaly_rule(db: Session) -> DetectionRule:
    rule_engine.ensure_builtin_rules(db)
    rule = db.execute(
        select(DetectionRule).where(DetectionRule.slug == "runtime.event_rate_anomaly")
    ).scalar_one_or_none()
    if rule is None:
        rule = DetectionRule(
            slug="runtime.event_rate_anomaly",
            name="Event rate anomaly",
            description="Event volume for one asset and event type exceeds its baseline.",
            category=EventCategory.RUNTIME.value,
            severity=Severity.MEDIUM.value,
            rule_type=DetectionRuleType.ANOMALY.value,
            source="BUILTIN",
            enabled=True,
            version=1,
            conditions={},
            create_incident=False,
            created_by="system",
        )
        db.add(rule)
        db.flush()
    return rule


def run(db: Session) -> dict[str, Any]:
    """Detect anomalous event rates and persist one event per asset/type/day."""
    settings = get_settings()
    if not settings.events_anomaly_enabled:
        return {"status": "DISABLED", "created": 0, "evaluated": 0}

    now = _now()
    recent_since = now - timedelta(hours=24)
    baseline_days = max(1, min(settings.events_anomaly_baseline_days, 30))
    baseline_since = recent_since - timedelta(days=baseline_days)
    min_count = max(1, settings.events_anomaly_min_count)
    multiplier = max(1.5, settings.events_anomaly_multiplier)

    recent = {
        (asset_id, event_type): (int(total or 0), last_seen)
        for asset_id, event_type, total, last_seen in db.execute(
            select(
                SecurityEvent.asset_id,
                SecurityEvent.event_type,
                func.sum(SecurityEvent.occurrence_count),
                func.max(SecurityEvent.last_seen_at),
            )
            .where(
                SecurityEvent.last_seen_at >= recent_since,
                SecurityEvent.event_type != "anomaly.event_rate",
            )
            .group_by(SecurityEvent.asset_id, SecurityEvent.event_type)
        ).all()
    }
    baseline = {
        (asset_id, event_type): int(total or 0)
        for asset_id, event_type, total in db.execute(
            select(
                SecurityEvent.asset_id,
                SecurityEvent.event_type,
                func.sum(SecurityEvent.occurrence_count),
            )
            .where(
                SecurityEvent.last_seen_at >= baseline_since,
                SecurityEvent.last_seen_at < recent_since,
                SecurityEvent.event_type != "anomaly.event_rate",
            )
            .group_by(SecurityEvent.asset_id, SecurityEvent.event_type)
        ).all()
    }

    rule = _anomaly_rule(db)
    created = 0
    evaluated = 0
    findings: list[dict[str, Any]] = []
    bucket = now.strftime("%Y-%m-%d")

    for (asset_id, event_type), (recent_count, last_seen) in recent.items():
        evaluated += 1
        baseline_total = baseline.get((asset_id, event_type), 0)
        baseline_mean = baseline_total / baseline_days
        if baseline_total == 0:
            threshold = min_count * 2.5
            ratio = None
        else:
            threshold = max(min_count, baseline_mean * multiplier)
            ratio = round(recent_count / baseline_mean, 2) if baseline_mean else None
        if recent_count < threshold:
            continue

        severity = Severity.HIGH.value if (ratio is None or ratio >= 10) else Severity.MEDIUM.value
        fingerprint = hashlib.sha256(
            f"anomaly|{asset_id}|{event_type}|{bucket}".encode()
        ).hexdigest()
        existing = db.execute(
            select(SecurityEvent).where(SecurityEvent.fingerprint == fingerprint)
        ).scalar_one_or_none()
        payload = {
            "asset_id": str(asset_id) if asset_id else None,
            "event_type": event_type,
            "recent_count": recent_count,
            "baseline_daily_mean": round(baseline_mean, 2),
            "baseline_days": baseline_days if baseline_total else 0,
            "ratio": ratio,
            "threshold": round(threshold, 2),
        }
        if existing is not None:
            existing.occurrence_count = recent_count
            existing.last_seen_at = last_seen or now
            existing.enrichment = {**existing.enrichment, "anomaly": payload}
            continue

        event = SecurityEvent(
            fingerprint=fingerprint,
            category=EventCategory.RUNTIME.value,
            source=EventSource.GENERIC.value,
            event_type="anomaly.event_rate",
            title=f"Event rate anomaly for {event_type}"[:500],
            description=(
                f"{recent_count} occurrences in the last 24h against a daily mean of "
                f"{round(baseline_mean, 2)}."
            ),
            severity=severity,
            asset_id=asset_id,
            detection_rule_id=rule.id,
            rule_slug=rule.slug,
            rule_version=rule.version,
            occurrence_count=recent_count,
            first_seen_at=recent_since,
            last_seen_at=last_seen or now,
            normalized={
                "rule_name": rule.name,
                "status": "anomaly",
            },
            indicators=[],
            enrichment={"anomaly": payload, "raw_truncated": False},
            risk_score=75 if severity == Severity.HIGH.value else 55,
        )
        db.add(event)
        created += 1
        findings.append(
            {
                "asset_id": str(asset_id) if asset_id else None,
                "event_type": event_type,
                **payload,
            }
        )

    rule.last_matched_at = now if created else rule.last_matched_at
    rule.match_count = int(rule.match_count or 0) + created
    db.flush()
    logger.info(
        "runtime anomaly pass finished",
        extra={"extra_fields": {"evaluated": evaluated, "created": created}},
    )
    return {
        "status": "SUCCEEDED",
        "evaluated": evaluated,
        "created": created,
        "anomalies": findings[:50],
        "baseline_days": baseline_days,
        "multiplier": multiplier,
        "min_count": min_count,
    }
