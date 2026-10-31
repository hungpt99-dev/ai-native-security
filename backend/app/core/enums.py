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
    SYNC_EPSS = "SYNC_EPSS"
    AI_RISK = "AI_RISK"
    AI_INVESTIGATE = "AI_INVESTIGATE"
    AI_REMEDIATE = "AI_REMEDIATE"
    AI_VERIFY = "AI_VERIFY"


# --------------------------------------------------------------------------- AI
class AIExecutionKind(StrEnum):
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    INVESTIGATION = "INVESTIGATION"
    REMEDIATION = "REMEDIATION"
    ASSISTANT = "ASSISTANT"


class AIExecutionStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    TIMED_OUT = "TIMED_OUT"
    RATE_LIMITED = "RATE_LIMITED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


class RiskLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


RISK_LEVEL_ORDER: dict[str, int] = {
    RiskLevel.CRITICAL.value: 0,
    RiskLevel.HIGH.value: 1,
    RiskLevel.MEDIUM.value: 2,
    RiskLevel.LOW.value: 3,
    RiskLevel.INFO.value: 4,
    RiskLevel.UNKNOWN.value: 5,
}


class InvestigationStatus(StrEnum):
    """Outcome of an AI investigation.

    ``NO_EVIDENCE_FOUND`` explicitly does **not** mean "safe": it means the
    platform could not find evidence either way.
    """

    CONFIRMED_IMPACT = "CONFIRMED_IMPACT"
    POTENTIAL_IMPACT = "POTENTIAL_IMPACT"
    NO_EVIDENCE_FOUND = "NO_EVIDENCE_FOUND"
    INCONCLUSIVE = "INCONCLUSIVE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


INVESTIGATION_STATUSES = tuple(status.value for status in InvestigationStatus)


class RemediationStrategy(StrEnum):
    DEPENDENCY_UPGRADE = "DEPENDENCY_UPGRADE"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    CODE_FIX = "CODE_FIX"
    COMPONENT_REMOVAL = "COMPONENT_REMOVAL"
    MITIGATION = "MITIGATION"
    NO_ACTION_AVAILABLE = "NO_ACTION_AVAILABLE"


REMEDIATION_STRATEGIES = tuple(strategy.value for strategy in RemediationStrategy)


class RemediationStatus(StrEnum):
    """End-to-end remediation lifecycle, shared by recommendation and decision."""

    DISCOVERED = "DISCOVERED"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    VALIDATING = "VALIDATING"
    VERIFIED = "VERIFIED"
    DEPLOYED = "DEPLOYED"
    CLOSED = "CLOSED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    REOPENED = "REOPENED"


REMEDIATION_STATUSES = tuple(status.value for status in RemediationStatus)

#: Allowed transitions of the remediation lifecycle. Enforced in the service
#: layer, exactly like ``ALLOWED_FINDING_TRANSITIONS`` for findings.
ALLOWED_REMEDIATION_TRANSITIONS: dict[str, set[str]] = {
    RemediationStatus.DISCOVERED.value: {
        RemediationStatus.TRIAGED.value,
        RemediationStatus.REJECTED.value,
    },
    RemediationStatus.TRIAGED.value: {
        RemediationStatus.INVESTIGATING.value,
        RemediationStatus.REJECTED.value,
    },
    RemediationStatus.INVESTIGATING.value: {
        RemediationStatus.REMEDIATION_PROPOSED.value,
        RemediationStatus.REJECTED.value,
    },
    RemediationStatus.REMEDIATION_PROPOSED.value: {
        RemediationStatus.AWAITING_APPROVAL.value,
        RemediationStatus.REJECTED.value,
    },
    RemediationStatus.AWAITING_APPROVAL.value: {
        RemediationStatus.APPROVED.value,
        RemediationStatus.REJECTED.value,
    },
    RemediationStatus.APPROVED.value: {
        RemediationStatus.VALIDATING.value,
        RemediationStatus.REJECTED.value,
    },
    RemediationStatus.VALIDATING.value: {
        RemediationStatus.VERIFIED.value,
        RemediationStatus.FAILED.value,
    },
    RemediationStatus.VERIFIED.value: {
        RemediationStatus.DEPLOYED.value,
        RemediationStatus.REOPENED.value,
    },
    RemediationStatus.DEPLOYED.value: {
        RemediationStatus.CLOSED.value,
        RemediationStatus.REOPENED.value,
    },
    RemediationStatus.FAILED.value: {
        RemediationStatus.REOPENED.value,
        RemediationStatus.REJECTED.value,
    },
    RemediationStatus.REOPENED.value: {
        RemediationStatus.TRIAGED.value,
        RemediationStatus.INVESTIGATING.value,
    },
    RemediationStatus.REJECTED.value: {RemediationStatus.REOPENED.value},
    RemediationStatus.CLOSED.value: {RemediationStatus.REOPENED.value},
}


class VerificationStatus(StrEnum):
    PENDING = "PENDING"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    PARTIALLY_FIXED = "PARTIALLY_FIXED"
    NEW_RISK_INTRODUCED = "NEW_RISK_INTRODUCED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


VERIFICATION_STATUSES = tuple(status.value for status in VerificationStatus)


class DecisionType(StrEnum):
    TRIAGE = "TRIAGE"
    CONFIRM = "CONFIRM"
    MARK_FALSE_POSITIVE = "MARK_FALSE_POSITIVE"
    ACCEPT_RISK = "ACCEPT_RISK"
    APPROVE_REMEDIATION = "APPROVE_REMEDIATION"
    REJECT_REMEDIATION = "REJECT_REMEDIATION"
    ACCEPT_VERIFICATION = "ACCEPT_VERIFICATION"
    REOPEN = "REOPEN"


DECISION_TYPES = tuple(decision.value for decision in DecisionType)


class FeedbackVerdict(StrEnum):
    ASSESSMENT_CORRECT = "ASSESSMENT_CORRECT"
    ASSESSMENT_INCORRECT = "ASSESSMENT_INCORRECT"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REMEDIATION_USEFUL = "REMEDIATION_USEFUL"
    REMEDIATION_INCORRECT = "REMEDIATION_INCORRECT"


FEEDBACK_VERDICTS = tuple(verdict.value for verdict in FeedbackVerdict)


class PolicyKind(StrEnum):
    RISK_SCORING = "RISK_SCORING"
    REMEDIATION = "REMEDIATION"
    DATA_SHARING = "DATA_SHARING"


POLICY_KINDS = tuple(kind.value for kind in PolicyKind)
