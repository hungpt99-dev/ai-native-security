"""Threat intelligence indicator management and matching.

Storage is exact-match on a normalized value. There is no fuzzy matching and no
third-party lookup at match time: an indicator either exists in the table or it
does not, and every match is attributed to the sources that supplied it.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.enums import INDICATOR_SOURCES, INDICATOR_TYPES, IndicatorSource
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.modules.threat_intel.models import ThreatIndicator, ThreatIntelIngest

logger = get_logger(__name__)

MAX_BATCH = 1000
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_MD5 = re.compile(r"^[a-f0-9]{32}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")


def _now() -> datetime:
    return datetime.now(UTC)


def normalize_value(indicator_type: str, value: str) -> str:
    """Canonicalize an indicator value, or reject it.

    Rejecting is deliberate: storing a malformed indicator would produce
    matches that cannot be defended during an investigation.
    """
    kind = (indicator_type or "").strip().upper()
    if kind not in INDICATOR_TYPES:
        raise ValidationError("Unsupported indicator type", details={"type": indicator_type})
    raw = (value or "").strip()
    if not raw or len(raw) > 512:
        raise ValidationError("Indicator value is empty or too long")

    if kind == "IP":
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise ValidationError("Invalid IP address") from exc
    if kind in {"SHA256", "MD5"}:
        lowered = raw.lower()
        pattern = _SHA256 if kind == "SHA256" else _MD5
        if not pattern.match(lowered):
            raise ValidationError(f"Invalid {kind} hash")
        return lowered
    if kind == "DOMAIN":
        lowered = raw.lower().rstrip(".")
        if lowered.startswith("*."):
            lowered = lowered[2:]
        if not _DOMAIN.match(lowered):
            raise ValidationError("Invalid domain")
        return lowered
    if kind == "EMAIL":
        lowered = raw.lower()
        if not _EMAIL.match(lowered):
            raise ValidationError("Invalid email address")
        return lowered
    if kind == "URL":
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValidationError("URL must be absolute http(s)")
        return raw[:512]
    raise ValidationError("Unsupported indicator type")


def upsert_indicators(
    db: Session,
    items: list[dict[str, Any]],
    *,
    source: str = IndicatorSource.MANUAL.value,
    actor: str = "system",
    source_ref: str | None = None,
) -> dict[str, Any]:
    if source not in INDICATOR_SOURCES:
        raise ValidationError("Unknown indicator source")
    if not items:
        raise ValidationError("At least one indicator is required")
    if len(items) > MAX_BATCH:
        raise ValidationError(f"A batch may contain at most {MAX_BATCH} indicators")

    now = _now()
    created = updated = rejected = 0
    errors: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for index, item in enumerate(items):
        try:
            kind = str(item.get("indicator_type") or item.get("type") or "").upper()
            value = normalize_value(kind, str(item.get("value") or ""))
        except ValidationError as exc:
            rejected += 1
            if len(errors) < 20:
                errors.append({"index": index, "error": exc.message})
            continue
        if (kind, value) in seen:
            continue
        seen.add((kind, value))

        severity = str(item.get("severity") or "HIGH").upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}:
            severity = "HIGH"
        confidence = item.get("confidence", 50)
        try:
            confidence = max(0, min(100, int(confidence)))
        except (TypeError, ValueError):
            confidence = 50
        raw_tags = item.get("tags")
        tags: list[Any] = raw_tags if isinstance(raw_tags, list) else []
        expires = item.get("expires_at")
        expires_at = None
        if isinstance(expires, datetime):
            expires_at = expires if expires.tzinfo else expires.replace(tzinfo=UTC)
        elif isinstance(expires, str):
            try:
                parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                expires_at = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except ValueError:
                expires_at = None

        existing = db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == kind,
                ThreatIndicator.value == value,
                ThreatIndicator.source == source,
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                ThreatIndicator(
                    indicator_type=kind,
                    value=value,
                    source=source,
                    source_ref=(source_ref or item.get("source_ref") or None),
                    severity=severity,
                    confidence=confidence,
                    description=(str(item.get("description"))[:4000] if item.get("description") else None),
                    tags=[str(tag)[:64] for tag in tags[:20]],
                    active=True,
                    first_seen_at=now,
                    last_seen_at=now,
                    expires_at=expires_at,
                    ingested_at=now,
                    metadata_json={"actor": actor},
                )
            )
            created += 1
        else:
            existing.last_seen_at = now
            existing.severity = severity or existing.severity
            existing.confidence = confidence
            existing.active = True
            if expires_at is not None:
                existing.expires_at = expires_at
            if item.get("description"):
                existing.description = str(item["description"])[:4000]
            updated += 1
    db.flush()

    ingest = ThreatIntelIngest(
        source=source,
        actor=actor[:120],
        received=len(items),
        created=created,
        updated=updated,
        rejected=rejected,
        errors=errors,
    )
    db.add(ingest)
    db.flush()
    logger.info(
        "threat indicators ingested",
        extra={
            "extra_fields": {
                "source": source,
                "created": created,
                "updated": updated,
                "rejected": rejected,
            }
        },
    )
    return {
        "received": len(items),
        "created": created,
        "updated": updated,
        "rejected": rejected,
        "errors": errors,
        "ingest_id": str(ingest.id),
    }


def match_indicators(
    db: Session, indicators: list[dict[str, Any]], *, limit: int = 50
) -> list[dict[str, Any]]:
    """Return active indicators matching the supplied (type, value) pairs."""
    if not indicators:
        return []
    now = _now()
    conditions = []
    normalized: list[tuple[str, str]] = []
    for item in indicators[:limit]:
        try:
            kind = str(item.get("type") or item.get("indicator_type") or "").upper()
            value = normalize_value(kind, str(item.get("value") or ""))
        except ValidationError:
            continue
        normalized.append((kind, value))
        conditions.append(
            (ThreatIndicator.indicator_type == kind) & (ThreatIndicator.value == value)
        )
    if not conditions:
        return []
    rows = db.execute(
        select(ThreatIndicator).where(
            or_(*conditions),
            ThreatIndicator.active.is_(True),
            or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > now),
        )
    ).scalars()
    matches = []
    for row in rows:
        matches.append(
            {
                "type": row.indicator_type,
                "value": row.value,
                "source": row.source,
                "source_ref": row.source_ref,
                "severity": row.severity,
                "confidence": row.confidence,
                "indicator_id": str(row.id),
            }
        )
    return matches


def list_indicators(
    db: Session,
    params: PageParams,
    *,
    indicator_type: str | None = None,
    source: str | None = None,
    value: str | None = None,
    active: bool | None = None,
) -> tuple[list[ThreatIndicator], int]:
    stmt = select(ThreatIndicator)
    if indicator_type:
        stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type.upper())
    if source:
        stmt = stmt.where(ThreatIndicator.source == source.upper())
    if value:
        stmt = stmt.where(ThreatIndicator.value.ilike(f"%{value.strip()[:200]}%"))
    if active is not None:
        stmt = stmt.where(ThreatIndicator.active.is_(active))
    stmt = stmt.order_by(ThreatIndicator.ingested_at.desc())
    return paginate(db, stmt, params)


def deactivate(db: Session, indicator_id: uuid.UUID) -> ThreatIndicator:
    indicator = db.get(ThreatIndicator, indicator_id)
    if indicator is None:
        raise NotFoundError("Indicator not found")
    indicator.active = False
    db.flush()
    return indicator


def summary(db: Session) -> dict[str, Any]:
    by_type = {
        kind: int(
            db.execute(
                select(func.count(ThreatIndicator.id)).where(
                    ThreatIndicator.indicator_type == kind,
                    ThreatIndicator.active.is_(True),
                )
            ).scalar_one()
        )
        for kind in INDICATOR_TYPES
    }
    by_source = [
        {"source": source, "count": int(count), "last_ingested_at": last}
        for source, count, last in db.execute(
            select(
                ThreatIndicator.source,
                func.count(ThreatIndicator.id),
                func.max(ThreatIndicator.ingested_at),
            ).group_by(ThreatIndicator.source)
        ).all()
    ]
    last_ingest = db.execute(
        select(ThreatIntelIngest).order_by(ThreatIntelIngest.created_at.desc()).limit(1)
    ).scalar_one_or_none()
    return {
        "active": int(
            db.execute(
                select(func.count(ThreatIndicator.id)).where(ThreatIndicator.active.is_(True))
            ).scalar_one()
        ),
        "by_type": by_type,
        "by_source": by_source,
        "last_ingest": (
            {
                "source": last_ingest.source,
                "created": last_ingest.created,
                "updated": last_ingest.updated,
                "rejected": last_ingest.rejected,
                "at": last_ingest.created_at.isoformat(),
            }
            if last_ingest
            else None
        ),
    }
