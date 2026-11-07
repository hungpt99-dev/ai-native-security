"""Deterministic detection rule engine.

Rules are data, not code:

    {"all": [{"field": "normalized.process", "op": "in", "value": ["bash", "sh"]}]}

Supported groups: ``all``, ``any``, ``not`` (nestable). Supported operators:
``exists``, ``eq``, ``ne``, ``in``, ``not_in``, ``contains``, ``not_contains``,
``startswith``, ``endswith``, ``regex``, ``gt``, ``gte``, ``lt``, ``lte``,
``in_cidr``, ``any_in``.

Why a DSL: a rule must be inspectable, versioned and testable without executing
user-supplied Python. Regex patterns are capped in length and evaluated against
bounded field values; IP rules use ``ipaddress`` rather than string prefix
matching, which would classify 10.0.0.1 as inside 10.0.0.0/8 by accident.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import (
    DetectionRuleSource,
    DetectionRuleType,
    EventCategory,
    Severity,
)
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.events.models import DetectionRule

logger = get_logger(__name__)

MAX_REGEX_LENGTH = 200
_MAX_VALUE_LENGTH = 4000

_GROUP_KEYS = {"all", "any", "not"}
_ALLOWED_OPS = {
    "exists",
    "eq",
    "ne",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "startswith",
    "endswith",
    "regex",
    "gt",
    "gte",
    "lt",
    "lte",
    "in_cidr",
    "any_in",
}
_ALLOWED_FIELDS = {
    "source",
    "category",
    "event_type",
    "severity",
    "title",
    "normalized.host",
    "normalized.process",
    "normalized.parent_process",
    "normalized.command_line",
    "normalized.user",
    "normalized.file_path",
    "normalized.remote_ip",
    "normalized.remote_port",
    "normalized.local_ip",
    "normalized.local_port",
    "normalized.protocol",
    "normalized.domain",
    "normalized.url",
    "normalized.hash",
    "normalized.rule_name",
    "normalized.status",
    "normalized.pod",
    "normalized.namespace",
    "normalized.node",
    "normalized.container.id",
    "normalized.container.name",
    "normalized.container.image",
}


def _validate_group(group: Any, *, path: str = "conditions") -> None:
    if not isinstance(group, dict) or not group:
        raise ValidationError(f"{path} must be a non-empty object")
    if len(group) != 1:
        raise ValidationError(f"{path} must contain exactly one of all/any/not")
    key, value = next(iter(group.items()))
    if key not in _GROUP_KEYS:
        raise ValidationError(f"{path}: unknown group '{key}'")
    if key == "not":
        if isinstance(value, dict) and (set(value) & _GROUP_KEYS):
            _validate_group(value, path=f"{path}.not")
        else:
            _validate_condition(value, path=f"{path}.not")
        return
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{path}.{key} must be a non-empty array")
    for index, item in enumerate(value):
        item_path = f"{path}.{key}[{index}]"
        if isinstance(item, dict) and (set(item) & _GROUP_KEYS):
            _validate_group(item, path=item_path)
        else:
            _validate_condition(item, path=item_path)


def _validate_condition(condition: Any, *, path: str) -> None:
    if not isinstance(condition, dict):
        raise ValidationError(f"{path} must be an object")
    field = condition.get("field")
    op = condition.get("op")
    if field not in _ALLOWED_FIELDS:
        raise ValidationError(f"{path}: field must be one of the documented event fields")
    if op not in _ALLOWED_OPS:
        raise ValidationError(f"{path}: unsupported operator")
    if op == "exists":
        if not isinstance(condition.get("value"), bool):
            raise ValidationError(f"{path}: exists requires a boolean value")
        return
    if "value" not in condition:
        raise ValidationError(f"{path}: value is required")
    value = condition["value"]
    if op in {"in", "not_in", "in_cidr", "any_in"}:
        if not isinstance(value, list) or not value or len(value) > 100:
            raise ValidationError(f"{path}: value must be a non-empty array (max 100)")
        if op == "in_cidr":
            for entry in value:
                try:
                    ipaddress.ip_network(str(entry), strict=False)
                except ValueError as exc:
                    raise ValidationError(f"{path}: invalid CIDR '{entry}'") from exc
    if op == "regex":
        if not isinstance(value, str) or len(value) > MAX_REGEX_LENGTH:
            raise ValidationError(f"{path}: regex must be a string of at most {MAX_REGEX_LENGTH} chars")
        try:
            re.compile(value)
        except re.error as exc:
            raise ValidationError(f"{path}: invalid regex") from exc


def validate_conditions(group: Any) -> dict[str, Any]:
    _validate_group(group)
    return group


def _resolve(document: dict[str, Any], field: str) -> Any:
    current: Any = document
    for part in field.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    if isinstance(current, str):
        return current[:_MAX_VALUE_LENGTH]
    return current


def _as_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _match_condition(condition: dict[str, Any], document: dict[str, Any]) -> bool:
    actual = _resolve(document, condition["field"])
    op = condition["op"]
    expected = condition.get("value")

    if op == "exists":
        present = actual is not None and actual != ""
        return present is bool(expected)
    if actual is None:
        return op in {"ne", "not_in", "not_contains"}

    if op == "eq":
        return str(actual).lower() == str(expected).lower()
    if op == "ne":
        return str(actual).lower() != str(expected).lower()
    if op in {"in", "not_in"}:
        values = {str(item).lower() for item in (expected or [])}
        present = str(actual).lower() in values
        return present if op == "in" else not present
    if op in {"contains", "not_contains"}:
        present = str(expected).lower() in str(actual).lower()
        return present if op == "contains" else not present
    if op == "startswith":
        return str(actual).lower().startswith(str(expected).lower())
    if op == "endswith":
        return str(actual).lower().endswith(str(expected).lower())
    if op == "regex":
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    if op in {"gt", "gte", "lt", "lte"}:
        left, right = _as_number(actual), _as_number(expected)
        if left is None or right is None:
            return False
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[op]
    if op == "in_cidr":
        try:
            address = ipaddress.ip_address(str(actual))
        except ValueError:
            return False
        for network in expected or []:
            try:
                if address in ipaddress.ip_network(str(network), strict=False):
                    return True
            except ValueError:
                continue
        return False
    if op == "any_in":
        if not isinstance(actual, list):
            actual = [actual]
        values = {str(item).lower() for item in (expected or [])}
        return any(str(item).lower() in values for item in actual)
    return False


def matches(group: dict[str, Any], document: dict[str, Any]) -> bool:
    """Evaluate a validated condition group against an event document."""
    key, value = next(iter(group.items()))
    items = value if isinstance(value, list) else []
    if key == "all":
        return all(
            matches(item, document)
            if isinstance(item, dict) and (set(item) & _GROUP_KEYS)
            else _match_condition(item, document)
            for item in items
        )
    if key == "any":
        return any(
            matches(item, document)
            if isinstance(item, dict) and (set(item) & _GROUP_KEYS)
            else _match_condition(item, document)
            for item in items
        )
    if key == "not":
        if isinstance(value, dict) and (set(value) & _GROUP_KEYS):
            return not matches(value, document)
        if not isinstance(value, dict):
            return True
        return not _match_condition(value, document)
    return False


# --------------------------------------------------------------- built-in rules
#: Conservative defaults. Each rule states what it detects and why the severity
#: is what it is; noisy detections do not create incidents on their own.
BUILTIN_RULES: tuple[dict[str, Any], ...] = (
    {
        "slug": "runtime.shell_in_container",
        "name": "Interactive shell in a container",
        "description": (
            "A shell process ran inside a container. Normal for debug images, "
            "unusual for production workloads."
        ),
        "category": EventCategory.RUNTIME.value,
        "severity": Severity.HIGH.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "all": [
                {"field": "normalized.container.image", "op": "exists", "value": True},
                {"field": "normalized.process", "op": "in",
                 "value": ["bash", "sh", "dash", "zsh", "ksh", "ash", "busybox"]},
            ]
        },
        "create_incident": False,
    },
    {
        "slug": "runtime.package_manager_in_container",
        "name": "Package installation inside a running container",
        "description": (
            "Package managers mutate a running container's filesystem and are a "
            "common persistence step after exploitation."
        ),
        "category": EventCategory.RUNTIME.value,
        "severity": Severity.MEDIUM.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "all": [
                {"field": "normalized.container.image", "op": "exists", "value": True},
                {"field": "normalized.process", "op": "in",
                 "value": ["apt", "apt-get", "apk", "yum", "dnf", "pip", "pip3", "npm", "yarn"]},
            ]
        },
        "create_incident": False,
    },
    {
        "slug": "runtime.sensitive_file_access",
        "name": "Sensitive credential file accessed",
        "description": (
            "A process opened a file that stores credentials or authentication "
            "material. The platform records the path; it does not read the file."
        ),
        "category": EventCategory.RUNTIME.value,
        "severity": Severity.HIGH.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "all": [
                {"field": "normalized.file_path", "op": "in", "value": [
                    "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
                    "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
                    "/home/*/.ssh/id_rsa", "/proc/self/environ",
                ]},
            ]
        },
        "create_incident": False,
    },
    {
        "slug": "runtime.crypto_mining",
        "name": "Cryptomining indicator",
        "description": "Command line references a known miner binary or mining pool.",
        "category": EventCategory.RUNTIME.value,
        "severity": Severity.CRITICAL.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "any": [
                {"field": "normalized.command_line", "op": "contains", "value": "xmrig"},
                {"field": "normalized.command_line", "op": "contains", "value": "minerd"},
                {"field": "normalized.command_line", "op": "contains", "value": "stratum+tcp"},
                {"field": "normalized.command_line", "op": "contains", "value": "cryptonight"},
            ]
        },
        "create_incident": True,
        "incident_priority": "P2",
    },
    {
        "slug": "runtime.reverse_shell",
        "name": "Reverse shell indicator",
        "description": "Command line matches a common reverse-shell construction.",
        "category": EventCategory.RUNTIME.value,
        "severity": Severity.CRITICAL.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "any": [
                {"field": "normalized.command_line", "op": "contains", "value": "/dev/tcp/"},
                {"field": "normalized.command_line", "op": "contains", "value": "nc -e"},
                {"field": "normalized.command_line", "op": "contains", "value": "ncat -e"},
                {"field": "normalized.command_line", "op": "contains", "value": "socat tcp"},
                {"all": [
                    {"field": "normalized.command_line", "op": "contains", "value": "bash -i"},
                    {"field": "normalized.command_line", "op": "contains", "value": "&>"},
                ]},
            ]
        },
        "create_incident": True,
        "incident_priority": "P2",
    },
    {
        "slug": "runtime.privilege_escalation",
        "name": "Privilege escalation attempt",
        "description": "A Falco rule or a privileged command indicates privilege escalation.",
        "category": EventCategory.RUNTIME.value,
        "severity": Severity.HIGH.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "any": [
                {"field": "normalized.rule_name", "op": "contains", "value": "privilege escalation"},
                {"field": "normalized.rule_name", "op": "contains", "value": "setuid"},
                {"field": "normalized.command_line", "op": "contains", "value": "chmod u+s"},
                {"field": "normalized.command_line", "op": "contains", "value": "chmod 4755"},
            ]
        },
        "create_incident": False,
    },
    {
        "slug": "runtime.container_escape",
        "name": "Container escape indicator",
        "description": (
            "Falco reported a namespace, mount or privileged-container event that "
            "is characteristic of a container escape attempt."
        ),
        "category": EventCategory.RUNTIME.value,
        "severity": Severity.CRITICAL.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "any": [
                {"field": "normalized.rule_name", "op": "contains", "value": "container escape"},
                {"field": "normalized.rule_name", "op": "contains", "value": "privileged container"},
                {"field": "normalized.rule_name", "op": "contains", "value": "mount launched"},
                {"field": "normalized.rule_name", "op": "contains", "value": "namespace change"},
            ]
        },
        "create_incident": True,
        "incident_priority": "P1",
    },
    {
        "slug": "network.suspicious_ports",
        "name": "Connection to a commonly abused port",
        "description": (
            "Outbound connection to a port frequently used by backdoors or C2. "
            "This is a lead, not proof; an allowlist decision belongs in a custom rule."
        ),
        "category": EventCategory.NETWORK.value,
        "severity": Severity.MEDIUM.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "all": [
                {"field": "normalized.remote_port", "op": "in", "value": [4444, 1337, 31337, 6667, 9001]},
            ]
        },
        "create_incident": False,
    },
    {
        "slug": "identity.repeated_auth_failure",
        "name": "Repeated authentication failures from one address",
        "description": (
            "Ten or more failed authentications from the same remote address "
            "within five minutes."
        ),
        "category": EventCategory.IDENTITY.value,
        "severity": Severity.HIGH.value,
        "rule_type": DetectionRuleType.THRESHOLD.value,
        "version": 1,
        "conditions": {
            "all": [
                {"field": "event_type", "op": "eq", "value": "auth.failure"},
            ]
        },
        "threshold": {"count": 10, "window_seconds": 300, "group_by": ["normalized.remote_ip"]},
        "create_incident": True,
        "incident_priority": "P2",
    },
    {
        "slug": "runtime.critical_falco_event",
        "name": "Critical Falco detection",
        "description": (
            "Falco classified this event as critical/emergency/alert. Falco's own "
            "severity is authoritative; the platform does not downgrade it."
        ),
        "category": EventCategory.RUNTIME.value,
        "severity": Severity.CRITICAL.value,
        "rule_type": DetectionRuleType.SIGNATURE.value,
        "version": 1,
        "conditions": {
            "all": [
                {"field": "source", "op": "eq", "value": "FALCO"},
                {"field": "severity", "op": "eq", "value": "CRITICAL"},
            ]
        },
        "create_incident": True,
        "incident_priority": "P1",
    },
)


def ensure_builtin_rules(db: Session) -> list[DetectionRule]:
    """Create missing built-in rules and upgrade them when their version moves.

    Custom rules are never touched. An operator who disables a built-in rule keeps
    it disabled: the upgrade path preserves ``enabled``.
    """
    existing = {
        rule.slug: rule
        for rule in db.execute(
            select(DetectionRule).where(DetectionRule.source == DetectionRuleSource.BUILTIN.value)
        ).scalars()
    }
    result: list[DetectionRule] = []
    for definition in BUILTIN_RULES:
        slug = definition["slug"]
        rule = existing.get(slug)
        if rule is None:
            rule = DetectionRule(
                slug=slug,
                name=definition["name"],
                description=definition.get("description"),
                category=definition["category"],
                severity=definition["severity"],
                rule_type=definition["rule_type"],
                version=definition["version"],
                conditions=definition["conditions"],
                threshold=definition.get("threshold"),
                create_incident=definition.get("create_incident", False),
                incident_priority=definition.get("incident_priority"),
                source=DetectionRuleSource.BUILTIN.value,
                enabled=True,
                created_by="system",
            )
            db.add(rule)
        elif rule.version < definition["version"]:
            rule.name = definition["name"]
            rule.description = definition.get("description")
            rule.category = definition["category"]
            rule.severity = definition["severity"]
            rule.rule_type = definition["rule_type"]
            rule.version = definition["version"]
            rule.conditions = definition["conditions"]
            rule.threshold = definition.get("threshold")
            rule.create_incident = definition.get("create_incident", False)
            rule.incident_priority = definition.get("incident_priority")
        result.append(rule)
    db.flush()
    return result


def enabled_rules(db: Session) -> list[DetectionRule]:
    return list(
        db.execute(
            select(DetectionRule)
            .where(DetectionRule.enabled.is_(True))
            .order_by(DetectionRule.rule_type, DetectionRule.slug)
        ).scalars()
    )


def event_document(event: Any) -> dict[str, Any]:
    """Flatten an event row (or a NormalizedEvent) into the match document."""
    if isinstance(event, dict):
        source = event.get("source")
        category = event.get("category")
        event_type = event.get("event_type")
        severity = event.get("severity")
        title = event.get("title")
        normalized = event.get("normalized") or {}
    else:
        source = getattr(event, "source", None)
        category = getattr(event, "category", None)
        event_type = getattr(event, "event_type", None)
        severity = getattr(event, "severity", None)
        title = getattr(event, "title", None)
        normalized = getattr(event, "normalized", {}) or {}
    return {
        "source": source,
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "title": title,
        "normalized": normalized,
    }


def rule_matches(rule: DetectionRule, document: dict[str, Any]) -> bool:
    conditions = rule.conditions or {}
    if not conditions:
        # ANOMALY rules are produced by the job itself; they have no field
        # conditions and must never match an inbound event.
        return False
    try:
        return matches(conditions, document)
    except (ValueError, TypeError, StopIteration):  # malformed legacy row: never crash ingestion
        logger.warning(
            "detection rule could not be evaluated",
            extra={"extra_fields": {"rule": rule.slug}},
        )
        return False


@dataclass
class ThresholdResult:
    matched: bool
    count: int
    group: dict[str, Any]
    window_seconds: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "group": self.group,
            "window_seconds": self.window_seconds,
        }


def evaluate_threshold(
    db: Session,
    rule: DetectionRule,
    *,
    now: datetime,
    limit: int,
    document: dict[str, Any] | None = None,
) -> ThresholdResult:
    """Count recent matching events in the same grouping bucket.

    The scan is bounded by ``limit`` and by the rule window. Grouping is applied
    before counting: ten failures from ten different addresses are ten separate
    low-signal events, not one password-spraying incident.
    """
    threshold = rule.threshold or {}
    window = max(30, min(int(threshold.get("window_seconds", 300)), 86400))
    group_by = [field for field in threshold.get("group_by", []) if field in _ALLOWED_FIELDS]
    since = now - timedelta(seconds=window)

    target: dict[str, Any] = {}
    if document is not None:
        for field in group_by:
            value = _resolve(document, field)
            if value is not None:
                target[field] = value
    if group_by and not target:
        # No grouping value on this event: it cannot be compared to a bucket.
        return ThresholdResult(False, 0, {}, window)

    from app.modules.events.models import SecurityEvent  # local import: avoid cycle

    candidates = db.execute(
        select(SecurityEvent)
        .where(
            SecurityEvent.last_seen_at >= since,
            SecurityEvent.category == rule.category,
        )
        .order_by(SecurityEvent.last_seen_at.desc())
        .limit(limit)
    ).scalars()
    matched: list[Any] = []
    for event in candidates:
        event_doc = event_document(event)
        if not rule_matches(rule, event_doc):
            continue
        if target and any(
            str(_resolve(event_doc, field)) != str(value) for field, value in target.items()
        ):
            continue
        matched.append(event)
    count = len(matched)
    required = max(1, int(threshold.get("count", 10)))
    return ThresholdResult(count >= required, count, target, window)


def rule_to_dict(rule: DetectionRule) -> dict[str, Any]:
    return {
        "id": str(rule.id),
        "slug": rule.slug,
        "name": rule.name,
        "description": rule.description,
        "category": rule.category,
        "severity": rule.severity,
        "rule_type": rule.rule_type,
        "source": rule.source,
        "enabled": rule.enabled,
        "version": rule.version,
        "conditions": rule.conditions,
        "threshold": rule.threshold,
        "create_incident": rule.create_incident,
        "incident_priority": rule.incident_priority,
        "match_count": rule.match_count,
        "last_matched_at": rule.last_matched_at.isoformat() if rule.last_matched_at else None,
    }


def utcnow() -> datetime:
    return datetime.now(UTC)
