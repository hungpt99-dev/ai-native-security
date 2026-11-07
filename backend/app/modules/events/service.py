"""Event ingestion: dedupe, enrich, detect, correlate, open incidents.

Order of operations for every event (deterministic, no model call):

1. resolve the asset (explicit id, container image, host),
2. fingerprint and dedupe (occurrence counters instead of row-per-log-line),
3. match threat indicators,
4. evaluate signature rules,
5. evaluate threshold rules that matched,
6. compute a deterministic risk score,
7. create or attach an incident when a rule asks for one.

The AI layer is downstream of this: it reads the resulting incident, never the
raw log stream.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    DetectionRuleType,
    EventCategory,
    SecurityEventStatus,
    Severity,
)
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.modules.assets.models import Asset
from app.modules.events import normalize as normalizer
from app.modules.events import rules as rule_engine
from app.modules.events.models import SecurityEvent, SecurityEventNote
from app.modules.security_intelligence.models import AssetSecurityProfile
from app.modules.threat_intel import service as threat_intel

logger = get_logger(__name__)

_SEVERITY_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
    Severity.UNKNOWN.value: 5,
}
_SEVERITY_BASE = {
    Severity.CRITICAL.value: 85,
    Severity.HIGH.value: 65,
    Severity.MEDIUM.value: 45,
    Severity.LOW.value: 25,
    Severity.INFO.value: 10,
    Severity.UNKNOWN.value: 45,
}


def _now() -> datetime:
    return datetime.now(UTC)


def worst_severity(values: list[str]) -> str:
    if not values:
        return Severity.UNKNOWN.value
    return sorted(values, key=lambda value: _SEVERITY_ORDER.get(value, 5))[0]


def list_events(
    db: Session,
    params: PageParams,
    *,
    categories: list[str] | None = None,
    sources: list[str] | None = None,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    asset_id: uuid.UUID | None = None,
    incident_id: uuid.UUID | None = None,
    asset_scope: frozenset[uuid.UUID] | None = None,
    search: str | None = None,
    since: datetime | None = None,
    sort_by: str = "last_seen_at",
    sort_order: str = "desc",
) -> tuple[list[SecurityEvent], int]:
    stmt = select(SecurityEvent)
    if asset_scope is not None:
        # A scoped key never sees unattributed telemetry.
        stmt = stmt.where(SecurityEvent.asset_id.in_(list(asset_scope)))
    if categories:
        stmt = stmt.where(SecurityEvent.category.in_(categories))
    if sources:
        stmt = stmt.where(SecurityEvent.source.in_(sources))
    if severities:
        stmt = stmt.where(SecurityEvent.severity.in_(severities))
    if statuses:
        stmt = stmt.where(SecurityEvent.status.in_(statuses))
    if asset_id:
        stmt = stmt.where(SecurityEvent.asset_id == asset_id)
    if incident_id:
        stmt = stmt.where(SecurityEvent.incident_id == incident_id)
    if since:
        stmt = stmt.where(SecurityEvent.last_seen_at >= since)
    if search:
        like = f"%{search.strip()[:200]}%"
        stmt = stmt.where(
            or_(
                SecurityEvent.title.ilike(like),
                SecurityEvent.event_type.ilike(like),
                SecurityEvent.rule_slug.ilike(like),
                SecurityEvent.normalized["command_line"].astext.ilike(like),
                SecurityEvent.normalized["remote_ip"].astext.ilike(like),
                SecurityEvent.normalized["file_path"].astext.ilike(like),
            )
        )
    columns = {
        "last_seen_at": SecurityEvent.last_seen_at,
        "first_seen_at": SecurityEvent.first_seen_at,
        "severity": SecurityEvent.severity,
        "occurrence_count": SecurityEvent.occurrence_count,
        "risk_score": SecurityEvent.risk_score,
    }
    column = columns.get(sort_by, SecurityEvent.last_seen_at)
    stmt = stmt.order_by(column.asc() if sort_order.lower() == "asc" else column.desc())
    return paginate(db, stmt, params)


def get_event_or_404(db: Session, event_id: uuid.UUID) -> SecurityEvent:
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise NotFoundError("Security event not found", details={"event_id": str(event_id)})
    return event


def notes(db: Session, event_id: uuid.UUID) -> list[SecurityEventNote]:
    return list(
        db.execute(
            select(SecurityEventNote)
            .where(SecurityEventNote.event_id == event_id)
            .order_by(SecurityEventNote.created_at.asc())
        ).scalars()
    )


# ----------------------------------------------------------------- asset resolve
def _find_asset_by_ref(db: Session, kind: str, ref: str) -> Asset | None:
    return db.execute(
        select(Asset).where(Asset.kind == kind, Asset.external_ref == ref)
    ).scalar_one_or_none()


def resolve_asset(
    db: Session,
    event: normalizer.NormalizedEvent,
    *,
    explicit_asset_id: uuid.UUID | None,
    allow_create: bool,
) -> tuple[uuid.UUID | None, str, dict[str, Any]]:
    """Resolve the event to an inventory asset.

    Returns ``(asset_id, asset_key, enrichment)``. ``asset_key`` is always
    non-empty so fingerprints are stable even for unresolved events.
    """
    if explicit_asset_id is not None:
        asset = db.get(Asset, explicit_asset_id)
        if asset is not None:
            return asset.id, str(asset.id), {"resolved": True, "match": "explicit"}

    hint = event.asset_hint
    if hint:
        asset = _find_asset_by_ref(db, hint["kind"], hint["external_ref"])
        if asset is None and allow_create:
            asset = Asset(
                name=hint["name"][:200],
                kind=hint["kind"],
                repo_url=None,
                external_ref=hint["external_ref"][:500],
                provider="NONE",
                default_branch="main",
                description="Auto-discovered from security telemetry",
            )
            try:
                # Savepoint: a concurrent worker inserting the same external_ref
                # must not roll back the rest of this ingestion batch.
                with db.begin_nested():
                    db.add(asset)
                    db.flush()
            except Exception:
                asset = _find_asset_by_ref(db, hint["kind"], hint["external_ref"])
        if asset is not None:
            return asset.id, str(asset.id), {
                "resolved": True,
                "match": "auto_created" if allow_create else "external_ref",
                "external_ref": hint["external_ref"],
            }
        return None, hint["external_ref"], {
            "resolved": False,
            "reason": "asset_not_found",
            "external_ref": hint["external_ref"],
        }
    return None, "unresolved", {"resolved": False, "reason": "no_asset_hint"}


def _asset_profile(db: Session, asset_id: uuid.UUID | None) -> AssetSecurityProfile | None:
    return db.get(AssetSecurityProfile, asset_id) if asset_id else None


def _risk_score(
    severity: str,
    profile: AssetSecurityProfile | None,
    threat_matches: list[dict[str, Any]],
) -> int:
    score = _SEVERITY_BASE.get(severity, 45)
    if profile is not None:
        score += {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 0}.get(
            (profile.criticality or "").upper(), 0
        )
        if profile.internet_exposed:
            score += 5
    if threat_matches:
        border = max(int(match.get("confidence") or 0) for match in threat_matches)
        score += 10 if border >= 70 else 5
    return max(0, min(100, score))


# --------------------------------------------------------------------- ingestion
def ingest_events(
    db: Session,
    payloads: list[normalizer.NormalizedEvent],
    *,
    actor: str = "sensor",
) -> dict[str, Any]:
    settings = get_settings()
    if not payloads:
        raise ValidationError("No events supplied")
    if len(payloads) > settings.events_max_batch:
        raise ValidationError(
            "Event batch exceeds the configured maximum",
            details={"max": settings.events_max_batch},
        )

    rule_engine.ensure_builtin_rules(db)
    enabled = rule_engine.enabled_rules(db)

    created = deduplicated = incidents_opened = 0
    auto_assets = 0
    results: list[dict[str, Any]] = []

    for event in payloads:
        allow_create = (
            settings.events_auto_create_assets
            and auto_assets < settings.events_max_auto_assets_per_batch
        )
        asset_id, asset_key, asset_enrichment = resolve_asset(
            db, event, explicit_asset_id=None, allow_create=allow_create
        )
        if asset_enrichment.get("match") == "auto_created":
            auto_assets += 1

        fingerprint = normalizer.fingerprint(event, asset_key=asset_key)

        if event.source_event_id:
            replay = db.execute(
                select(SecurityEvent).where(
                    SecurityEvent.source == event.source,
                    SecurityEvent.source_event_id == event.source_event_id,
                )
            ).scalar_one_or_none()
            if replay is not None:
                deduplicated += 1
                results.append(
                    {"id": str(replay.id), "deduplicated": True, "reason": "source_event_id"}
                )
                continue

        threat_matches = threat_intel.match_indicators(db, event.indicators)
        document = {
            "source": event.source,
            "category": event.category,
            "event_type": event.event_type,
            "severity": event.severity,
            "title": event.title,
            "normalized": event.normalized,
        }

        existing = db.execute(
            select(SecurityEvent).where(SecurityEvent.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if existing is not None:
            existing.occurrence_count = int(existing.occurrence_count or 1) + 1
            existing.last_seen_at = max(existing.last_seen_at, event.occurred_at)
            existing.severity = worst_severity([existing.severity, event.severity])
            enrichment = dict(existing.enrichment or {})
            if threat_matches:
                merged = {
                    (item["type"], item["value"]): item
                    for item in enrichment.get("threat_matches", []) + threat_matches
                }
                enrichment["threat_matches"] = list(merged.values())
            enrichment.setdefault("dedupe", {})
            enrichment["dedupe"]["occurrences"] = existing.occurrence_count
            enrichment["dedupe"]["last_ingested_at"] = _now().isoformat()
            existing.enrichment = enrichment
            profile = _asset_profile(db, existing.asset_id)
            existing.risk_score = _risk_score(existing.severity, profile, threat_matches)
            db.flush()
            deduplicated += 1
            results.append({"id": str(existing.id), "deduplicated": True})
            continue

        matched_rules = [rule for rule in enabled if rule_engine.rule_matches(rule, document)]
        matched_signatures = [
            rule for rule in matched_rules if rule.rule_type != DetectionRuleType.THRESHOLD.value
        ]
        matched_signatures.sort(
            key=lambda rule: (_SEVERITY_ORDER.get(rule.severity, 5), rule.slug)
        )
        primary_rule = matched_signatures[0] if matched_signatures else None

        severity = event.severity
        if primary_rule is not None:
            severity = worst_severity([severity, primary_rule.severity])

        row = SecurityEvent(
            fingerprint=fingerprint,
            category=event.category,
            source=event.source,
            source_event_id=event.source_event_id,
            event_type=event.event_type,
            title=event.title[:500],
            description=event.description,
            severity=severity,
            status=SecurityEventStatus.OPEN.value,
            asset_id=asset_id,
            detection_rule_id=primary_rule.id if primary_rule else None,
            rule_slug=primary_rule.slug if primary_rule else None,
            rule_version=primary_rule.version if primary_rule else None,
            occurrence_count=1,
            first_seen_at=event.occurred_at,
            last_seen_at=event.occurred_at,
            raw=event.raw,
            normalized=event.normalized,
            indicators=event.indicators,
            enrichment={
                **asset_enrichment,
                "asset": asset_enrichment,
                "threat_matches": threat_matches,
                "matched_rules": [
                    {"slug": rule.slug, "severity": rule.severity, "version": rule.version}
                    for rule in matched_rules
                ],
                "raw_truncated": event.raw_truncated,
                "dedupe": {"occurrences": 1, "first_ingested_at": _now().isoformat()},
            },
        )
        db.add(row)
        db.flush()

        profile = _asset_profile(db, asset_id)
        threshold_hit = None
        for rule in matched_rules:
            rule.last_matched_at = _now()
            rule.match_count = int(rule.match_count or 0) + 1
            if rule.rule_type != DetectionRuleType.THRESHOLD.value or not rule.threshold:
                continue
            result = rule_engine.evaluate_threshold(
                db,
                rule,
                now=_now(),
                limit=settings.events_threshold_scan_limit,
                document=document,
            )
            if result.matched:
                threshold_hit = (rule, result)
                severity = worst_severity([severity, rule.severity])
                row.severity = severity

        if threshold_hit is not None:
            rule, result = threshold_hit
            row.enrichment = {
                **row.enrichment,
                "threshold": {"rule": rule.slug, **result.as_dict()},
            }
            if row.detection_rule_id is None:
                row.detection_rule_id = rule.id
                row.rule_slug = rule.slug
                row.rule_version = rule.version

        row.risk_score = _risk_score(severity, profile, threat_matches)

        incident_rule = threshold_hit[0] if threshold_hit else None
        if incident_rule is None and primary_rule is not None and primary_rule.create_incident:
            incident_rule = primary_rule
        if incident_rule is not None:
            from app.modules.incidents import service as incidents_service

            incident = incidents_service.create_or_attach_from_event(
                db,
                row,
                rule_slug=incident_rule.slug,
                rule_priority=incident_rule.incident_priority,
                actor=actor,
            )
            incidents_opened += 1
            row.enrichment = {
                **row.enrichment,
                "incident": {"id": str(incident.id), "priority": incident.priority},
            }

        created += 1
        results.append(
            {
                "id": str(row.id),
                "deduplicated": False,
                "severity": row.severity,
                "incident_id": str(row.incident_id) if row.incident_id else None,
            }
        )

    db.flush()
    logger.info(
        "security events ingested",
        extra={
            "extra_fields": {
                "received": len(payloads),
                "created": created,
                "deduplicated": deduplicated,
                "incidents": incidents_opened,
                "auto_assets": auto_assets,
            }
        },
    )
    return {
        "received": len(payloads),
        "created": created,
        "deduplicated": deduplicated,
        "incident_attachments": incidents_opened,
        "auto_created_assets": auto_assets,
        "results": results,
    }


def ingest_falco(db: Session, payload: dict[str, Any] | list[Any], *, actor: str = "falco") -> dict[str, Any]:
    items = payload if isinstance(payload, list) else [payload]
    normalized = [normalizer.normalize_falco(item) for item in items if isinstance(item, dict)]
    if not normalized:
        raise ValidationError("Falco payload contained no alert objects")
    return ingest_events(db, normalized, actor=actor)


def ingest_generic(db: Session, payloads: list[dict[str, Any]], *, actor: str = "sensor") -> dict[str, Any]:
    normalized = [normalizer.normalize_generic(item) for item in payloads]
    return ingest_events(db, normalized, actor=actor)


# ------------------------------------------------------------------- lifecycle
def acknowledge(db: Session, event: SecurityEvent, *, actor: str) -> SecurityEvent:
    if event.status != SecurityEventStatus.OPEN.value:
        raise ValidationError("Only open events can be acknowledged")
    event.status = SecurityEventStatus.ACKNOWLEDGED.value
    event.acknowledged_at = _now()
    db.flush()
    return event


def close(db: Session, event: SecurityEvent, *, actor: str, reason: str | None = None) -> SecurityEvent:
    if event.status == SecurityEventStatus.CLOSED.value:
        return event
    event.status = SecurityEventStatus.CLOSED.value
    event.closed_at = _now()
    if reason:
        db.add(
            SecurityEventNote(event_id=event.id, author=actor[:120], body=reason[:4000])
        )
    db.flush()
    return event


def add_note(db: Session, event: SecurityEvent, *, body: str, author: str) -> SecurityEventNote:
    if not body.strip():
        raise ValidationError("Note body cannot be empty")
    note = SecurityEventNote(event_id=event.id, author=author[:120], body=body[:4000])
    db.add(note)
    db.flush()
    return note


def summary(db: Session, *, window_hours: int = 24) -> dict[str, Any]:
    since = _now() - timedelta(hours=max(1, min(window_hours, 24 * 30)))
    by_category = {
        category: int(
            db.execute(
                select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.category == category, SecurityEvent.last_seen_at >= since
                )
            ).scalar_one()
        )
        for category in EventCategory
    }
    by_severity = {
        severity: int(
            db.execute(
                select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.severity == severity, SecurityEvent.last_seen_at >= since
                )
            ).scalar_one()
        )
        for severity in _SEVERITY_ORDER
    }
    total = int(
        db.execute(
            select(func.count(SecurityEvent.id)).where(SecurityEvent.last_seen_at >= since)
        ).scalar_one()
    )
    open_events = int(
        db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.status == SecurityEventStatus.OPEN.value
            )
        ).scalar_one()
    )
    last_seen = db.execute(select(func.max(SecurityEvent.last_seen_at))).scalar_one()
    per_hour = [
        {"hour": hour.isoformat(), "count": int(count)}
        for hour, count in db.execute(
            select(
                func.date_trunc("hour", SecurityEvent.last_seen_at).label("hour"),
                func.count(SecurityEvent.id),
            )
            .where(SecurityEvent.last_seen_at >= since)
            .group_by("hour")
            .order_by("hour")
        ).all()
    ]
    return {
        "window_hours": window_hours,
        "total": total,
        "open": open_events,
        "by_category": by_category,
        "by_severity": by_severity,
        "last_event_at": last_seen.isoformat() if last_seen else None,
        "per_hour": per_hour,
    }
