"""Shared enumerations used across modules and by the API layer."""

from __future__ import annotations

from enum import StrEnum


class Provider(StrEnum):
    GITHUB = "GITHUB"
    GITLAB = "GITLAB"


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


ACTIVE_SCAN_STATUSES = (ScanStatus.PENDING.value, ScanStatus.RUNNING.value)


class ScanTrigger(StrEnum):
    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"


class ScannerExecutionStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    SKIPPED = "SKIPPED"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
    Severity.UNKNOWN.value: 5,
}


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    RESOLVED = "RESOLVED"


#: Statuses that represent an active (unresolved) finding.
ACTIVE_FINDING_STATUSES = (
    FindingStatus.OPEN.value,
    FindingStatus.CONFIRMED.value,
    FindingStatus.ACCEPTED_RISK.value,
)


ALLOWED_FINDING_TRANSITIONS: dict[str, set[str]] = {
    FindingStatus.OPEN.value: {
        FindingStatus.CONFIRMED.value,
        FindingStatus.FALSE_POSITIVE.value,
        FindingStatus.ACCEPTED_RISK.value,
        FindingStatus.RESOLVED.value,
    },
    FindingStatus.CONFIRMED.value: {
        FindingStatus.FALSE_POSITIVE.value,
        FindingStatus.ACCEPTED_RISK.value,
        FindingStatus.RESOLVED.value,
        FindingStatus.OPEN.value,
    },
    FindingStatus.FALSE_POSITIVE.value: {
        FindingStatus.OPEN.value,
        FindingStatus.CONFIRMED.value,
    },
    FindingStatus.ACCEPTED_RISK.value: {
        FindingStatus.OPEN.value,
        FindingStatus.CONFIRMED.value,
        FindingStatus.RESOLVED.value,
    },
    FindingStatus.RESOLVED.value: {
        FindingStatus.OPEN.value,
        FindingStatus.CONFIRMED.value,
        FindingStatus.FALSE_POSITIVE.value,
    },
}


class FindingEvent(StrEnum):
    DETECTED = "DETECTED"
    REDETECTED = "REDETECTED"
    STATUS_CHANGED = "STATUS_CHANGED"
    AUTO_RESOLVED = "AUTO_RESOLVED"
    REOPENED = "REOPENED"
    ENRICHED = "ENRICHED"


class SbomFormat(StrEnum):
    CYCLONEDX_JSON = "CYCLONEDX_JSON"
    SPDX_JSON = "SPDX_JSON"


class VulnerabilitySource(StrEnum):
    OSV = "OSV"
    NVD = "NVD"
    CISA_KEV = "CISA_KEV"


class SyncStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class JobKind(StrEnum):
    SCAN = "SCAN"
    SYNC_OSV = "SYNC_OSV"
    SYNC_NVD = "SYNC_NVD"
    SYNC_KEV = "SYNC_KEV"
