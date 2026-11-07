"""Event normalization.

The platform accepts a small number of well-defined payload shapes and turns
each into one canonical document. Sensors are untrusted: every string is
bounded, control characters are stripped, and the original payload is truncated
and redacted before it is stored.

Canonical ``normalized`` keys (all optional, absent means unknown):

    host, container{id,name,image}, pod, namespace, node, process,
    parent_process, command_line, user, file_path, remote_ip, remote_port,
    local_ip, local_port, protocol, domain, url, hash, rule_name, status, count

``unknown`` is never encoded as a default value. A missing remote port stays
absent; rules that need it simply do not match.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from app.core.enums import EventCategory, EventSource, Severity
from app.core.security import redact_text

MAX_RAW_BYTES = 16 * 1024
MAX_STRING = 2000
MAX_FIELD = 500
MAX_INDICATORS = 20
MAX_BATCH = 500

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DOMAIN = re.compile(
    r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: Falco priority -> platform severity. Falco's own scale is 8 levels; mapping
#: is explicit so a new Falco priority cannot silently become "UNKNOWN".
FALCO_PRIORITY: dict[str, str] = {
    "emergency": Severity.CRITICAL.value,
    "alert": Severity.CRITICAL.value,
    "critical": Severity.CRITICAL.value,
    "error": Severity.HIGH.value,
    "warning": Severity.MEDIUM.value,
    "notice": Severity.LOW.value,
    "informational": Severity.INFO.value,
    "debug": Severity.INFO.value,
}

#: Falco tags that move an event out of the generic runtime bucket.
_CATEGORY_TAGS: tuple[tuple[str, str], ...] = (
    ("network", EventCategory.NETWORK.value),
    ("k8s_audit", EventCategory.IDENTITY.value),
    ("aws_cloudtrail", EventCategory.IDENTITY.value),
    ("filesystem", EventCategory.RUNTIME.value),
)


class NormalizationError(ValueError):
    """The payload cannot be represented as a security event."""


@dataclass
class NormalizedEvent:
    category: str
    source: str
    event_type: str
    title: str
    severity: str
    description: str | None = None
    source_event_id: str | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    normalized: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    indicators: list[dict[str, str]] = field(default_factory=list)
    raw_truncated: bool = False
    #: Asset hint resolved from the payload; the service turns it into an asset.
    asset_hint: dict[str, str] | None = None

    def identity_key(self) -> str:
        """Primary entity used for deduplication.

        Order matters: a file access and a process execution with the same rule
        must not collapse into one row, so the first available identity wins.
        """
        norm = self.normalized
        container = norm.get("container") or {}
        container_id = container.get("id") or container.get("name") or container.get("image") or ""
        parts = [
            norm.get("process") or "",
            norm.get("command_line") or "",
            norm.get("file_path") or "",
            norm.get("remote_ip") or "",
            str(norm.get("remote_port") or ""),
            norm.get("hash") or "",
            norm.get("domain") or "",
            norm.get("user") or "",
            container_id,
        ]
        meaningful = [part for part in parts if part]
        return "|".join(meaningful) if meaningful else (norm.get("rule_name") or self.title)


def _clean(value: Any, limit: int = MAX_FIELD) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    text = _CONTROL.sub("", text).strip()
    if not text:
        return None
    return text[:limit]


def _port(value: Any) -> int | None:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def extract_indicators(normalized: dict[str, Any], *, limit: int = MAX_INDICATORS) -> list[dict[str, str]]:
    """Extract threat-intelligence indicators from normalized fields.

    Deliberately conservative: only values the platform itself parsed (an IP
    field, a hash field, a URL host) plus domains/hashes found in the command
    line. Random substrings from log text are not indicators.
    """
    found: dict[tuple[str, str], dict[str, str]] = {}

    def add(kind: str, value: str | None) -> None:
        if not value or len(found) >= limit:
            return
        cleaned = value.strip().strip("'\"").rstrip(".,);]").lower()
        if not cleaned:
            return
        if kind == "IP":
            cleaned = _valid_ip(cleaned) or ""
        if not cleaned:
            return
        if kind == "DOMAIN" and "." not in cleaned:
            return
        found[(kind, cleaned)] = {"type": kind, "value": cleaned}

    add("IP", normalized.get("remote_ip"))
    add("IP", normalized.get("local_ip"))
    add("SHA256", normalized.get("hash"))
    add("URL", normalized.get("url"))
    add("DOMAIN", normalized.get("domain"))

    command = normalized.get("command_line") or ""
    for match in _SHA256.findall(command)[:5]:
        add("SHA256", match)
    for match in _IPV4.findall(command)[:5]:
        add("IP", match)
    for match in _DOMAIN.findall(command)[:8]:
        lowered = match.lower()
        if lowered.endswith((".local", ".internal", ".arpa")):
            continue
        add("DOMAIN", lowered)
    return list(found.values())


def _json_safe(payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Bound and redact the raw payload without losing its shape."""
    truncated = False
    safe: dict[str, Any] = {}
    for key, value in list(payload.items())[:60]:
        if isinstance(value, str):
            safe[key] = redact_text(value[:MAX_STRING])
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[key] = value
        elif isinstance(value, dict):
            nested = {str(k)[:80]: _clean(v, MAX_FIELD) for k, v in list(value.items())[:40]}
            safe[str(key)[:80]] = nested
        elif isinstance(value, list):
            safe[str(key)[:80]] = [_clean(item, 300) for item in value[:40]]
        else:
            safe[str(key)[:80]] = _clean(value, 300)
    serialized = repr(safe)
    if len(serialized) > MAX_RAW_BYTES:
        truncated = True
        safe = {"truncated": True, "preview": redact_text(serialized[:MAX_RAW_BYTES])}
    return safe, truncated


def _slug(value: str, prefix: str = "") -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:120]
    return f"{prefix}{slug}" if prefix else slug


def normalize_falco(payload: dict[str, Any]) -> NormalizedEvent:
    """Normalize a Falco HTTP output payload.

    Falco's ``http_output`` posts one JSON object per alert (or a list when
    batched). Both are accepted. Field names come from Falco's output_fields and
    are used only when present.
    """
    if not isinstance(payload, dict):
        raise NormalizationError("Falco payload must be a JSON object")
    raw_fields = payload.get("output_fields")
    fields: dict[str, Any] = raw_fields if isinstance(raw_fields, dict) else {}
    rule = _clean(payload.get("rule"), MAX_FIELD) or "Falco rule"
    priority = (_clean(payload.get("priority")) or "warning").lower()
    severity = FALCO_PRIORITY.get(priority, Severity.UNKNOWN.value)
    tags_value = payload.get("tags")
    tags = tags_value if isinstance(tags_value, list) else []

    category = EventCategory.RUNTIME.value
    for tag, mapped in _CATEGORY_TAGS:
        if any(str(tag) in str(item).lower() for item in tags):
            category = mapped
            break

    def field_value(*keys: str) -> str | None:
        for key in keys:
            value = fields.get(key)
            cleaned = _clean(value)
            if cleaned:
                return cleaned
        return None

    container_id = field_value("container.id")
    container_name = field_value("container.name")
    container_image: str | None = field_value(
        "container.image.repository", "container.image.name"
    )
    if container_image:
        image_tag = field_value("container.image.tag")
        if image_tag and ":" not in container_image:
            container_image = f"{container_image}:{image_tag}"

    normalized: dict[str, Any] = {}
    candidates: dict[str, Any] = {
        "host": field_value("hostname", "host.name"),
        "process": field_value("proc.name"),
        "parent_process": field_value("proc.pname"),
        "command_line": field_value("proc.cmdline", "proc.exepath"),
        "user": field_value("user.name", "user.uid"),
        "file_path": field_value("fd.name", "evt.abspath"),
        "remote_ip": field_value("fd.rip", "evt.arg.sip"),
        "local_ip": field_value("fd.lip"),
        "domain": field_value("fd.sip.name", "fd.rip.name"),
        "protocol": field_value("fd.l4proto", "net.protocol"),
        "rule_name": rule,
        "status": field_value("evt.type"),
    }
    for key, value in candidates.items():
        if value:
            normalized[key] = value
    remote_port = _port(field_value("fd.rport", "evt.arg.sport"))
    local_port = _port(field_value("fd.lport"))
    if remote_port:
        normalized["remote_port"] = remote_port
    if local_port:
        normalized["local_port"] = local_port
    if container_id or container_name or container_image:
        normalized["container"] = {
            key: value
            for key, value in {
                "id": container_id,
                "name": container_name,
                "image": container_image,
            }.items()
            if value
        }
    pod = field_value("k8s.pod.name")
    namespace = field_value("k8s.ns.name")
    node = field_value("k8s.node.name")
    if pod:
        normalized["pod"] = pod
    if namespace:
        normalized["namespace"] = namespace
    if node:
        normalized["node"] = node

    hint: dict[str, str] | None = None
    if container_image:
        hint = {"kind": "CONTAINER_IMAGE", "external_ref": f"docker://{container_image}",
                "name": container_image}
    elif normalized.get("host"):
        hint = {"kind": "HOST", "external_ref": f"host://{normalized['host']}",
                "name": normalized["host"]}

    occurred_at = _parse_time(payload.get("time"))
    raw, truncated = _json_safe({k: v for k, v in payload.items() if k != "output_fields"})
    return NormalizedEvent(
        category=category,
        source=EventSource.FALCO.value,
        event_type=_slug(rule, prefix="falco."),
        title=rule[:500],
        severity=severity,
        description=redact_text(_clean(payload.get("output"), 4000) or "")[:4000] or None,
        source_event_id=_clean(payload.get("uuid"), 200),
        occurred_at=occurred_at,
        normalized=normalized,
        raw=raw,
        indicators=extract_indicators(normalized),
        raw_truncated=truncated,
        asset_hint=hint,
    )


def normalize_generic(payload: dict[str, Any]) -> NormalizedEvent:
    """Normalize the documented generic ingestion payload.

    ``normalized`` is the same canonical document described at module level;
    unrecognized keys are ignored on purpose. The API schema validates the
    envelope before this function runs.
    """
    if not isinstance(payload, dict):
        raise NormalizationError("Event payload must be a JSON object")
    event_type = _clean(payload.get("event_type"), 160)
    if not event_type:
        raise NormalizationError("event_type is required")

    normalized: dict[str, Any] = {}
    raw_incoming = payload.get("normalized")
    incoming: dict[str, Any] = raw_incoming if isinstance(raw_incoming, dict) else {}
    allowed = (
        "host", "process", "parent_process", "command_line", "user", "file_path",
        "remote_ip", "local_ip", "domain", "url", "hash", "rule_name", "status",
    )
    for key in allowed:
        value = _clean(incoming.get(key))
        if value:
            normalized[key] = value
    for key in ("remote_port", "local_port"):
        port = _port(incoming.get(key))
        if port:
            normalized[key] = port
    for key in ("pod", "namespace", "node"):
        value = _clean(incoming.get(key))
        if value:
            normalized[key] = value
    container_raw = incoming.get("container")
    if isinstance(container_raw, dict):
        container = {
            key: value
            for key, value in {
                "id": _clean(container_raw.get("id")),
                "name": _clean(container_raw.get("name")),
                "image": _clean(container_raw.get("image")),
            }.items()
            if value
        }
        if container:
            normalized["container"] = container

    host = normalized.get("host")
    image = (normalized.get("container") or {}).get("image")
    hint: dict[str, str] | None = None
    if image:
        hint = {"kind": "CONTAINER_IMAGE", "external_ref": f"docker://{image}", "name": image}
    elif host:
        hint = {"kind": "HOST", "external_ref": f"host://{host}", "name": host}

    severity = str(payload.get("severity") or Severity.MEDIUM.value).upper()
    if severity not in {item.value for item in Severity}:
        raise NormalizationError("severity is not a known level")
    category = str(payload.get("category") or EventCategory.RUNTIME.value).upper()
    if category not in {item.value for item in EventCategory}:
        raise NormalizationError("category is not a known domain")

    raw_incoming = payload.get("raw")
    raw, truncated = _json_safe(raw_incoming if isinstance(raw_incoming, dict) else {})
    indicators = extract_indicators(normalized)
    explicit = payload.get("indicators")
    if isinstance(explicit, list):
        for item in explicit[:MAX_INDICATORS]:
            if isinstance(item, dict) and item.get("type") and item.get("value"):
                indicators.append(
                    {"type": str(item["type"]).upper()[:16], "value": _clean(item["value"], 512) or ""}
                )

    return NormalizedEvent(
        category=category,
        source=EventSource.GENERIC.value,
        event_type=event_type,
        title=_clean(payload.get("title"), 500) or event_type,
        severity=severity,
        description=_clean(payload.get("description"), 4000),
        source_event_id=_clean(payload.get("source_event_id"), 200),
        occurred_at=_parse_time(payload.get("occurred_at")),
        normalized=normalized,
        raw=raw,
        indicators=[item for item in indicators if item.get("value")][:MAX_INDICATORS],
        raw_truncated=truncated,
        asset_hint=hint,
    )


def _parse_time(value: Any) -> datetime:
    """Parse an ISO timestamp; an unparseable time is "now", never a guess."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)
    return datetime.now(UTC)


def fingerprint(event: NormalizedEvent, *, asset_key: str) -> str:
    """Stable dedupe identity: source, type, asset, rule and primary entity."""
    payload = "|".join(
        [
            event.source,
            event.event_type,
            asset_key,
            event.category,
            event.identity_key(),
        ]
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def url_host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None
