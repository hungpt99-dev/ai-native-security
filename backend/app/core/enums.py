"""Shared enumerations used across modules and by the API layer."""

from __future__ import annotations

from enum import StrEnum


class Provider(StrEnum):
    GITHUB = "GITHUB"
    GITLAB = "GITLAB"
    #: Non-git sources (container registries, cloud APIs) use their own kind.
    NONE = "NONE"


class AssetKind(StrEnum):
    """What an inventory row describes.

    Repositories were the first asset type; infrastructure and runtime security
    add the others. One table keeps ownership, criticality and findings
    consistent across domains instead of forking the inventory.
    """

    REPOSITORY = "REPOSITORY"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    HOST = "HOST"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    KUBERNETES_WORKLOAD = "KUBERNETES_WORKLOAD"
    API_SERVICE = "API_SERVICE"


ASSET_KINDS = tuple(kind.value for kind in AssetKind)



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
    # Continuous SBOM lifecycle. These never run the full scanner pipeline.
    SBOM_CHANGE_CHECK = "SBOM_CHANGE_CHECK"
    SBOM_GENERATE = "SBOM_GENERATE"
    SBOM_VULNERABILITY_REASSESSMENT = "SBOM_VULNERABILITY_REASSESSMENT"
    #: Infrastructure / IaC / container image assessment.
    INFRA_SCAN = "INFRA_SCAN"
    #: Deterministic statistical pass over stored security events.
    RUNTIME_ANOMALY_SCAN = "RUNTIME_ANOMALY_SCAN"


# --------------------------------------------------------------- SBOM lifecycle
class SbomSnapshotReason(StrEnum):
    """Why a snapshot was generated. Provenance only; never inferred data."""

    FULL_SCAN = "FULL_SCAN"
    INITIAL = "INITIAL"
    DEPENDENCY_CHANGE = "DEPENDENCY_CHANGE"
    WEBHOOK = "WEBHOOK"
    MANUAL = "MANUAL"
    #: The previous snapshot predates commit tracking, so composition can only
    #: be re-established by generating a fresh baseline.
    BASELINE = "BASELINE"


class SbomGenerationStatus(StrEnum):
    """State of a stored snapshot document.

    A failed generation never creates a snapshot row: it is recorded as an
    ``SBOM_GENERATION`` monitoring run with status FAILED, so a snapshot that
    exists always has an intact document behind ``storage_key``.
    """

    READY = "READY"


class SbomFreshness(StrEnum):
    """Does the latest snapshot still describe the current repository?

    ``UNKNOWN`` is a first-class state: when the provider cannot be reached and
    the head commit differs, the platform must not claim the SBOM is current.
    """

    MISSING = "MISSING"
    CURRENT = "CURRENT"
    STALE = "STALE"
    PENDING = "PENDING"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class SbomMonitoringKind(StrEnum):
    DEPENDENCY_CHECK = "DEPENDENCY_CHECK"
    SBOM_GENERATION = "SBOM_GENERATION"
    VULNERABILITY_REASSESSMENT = "VULNERABILITY_REASSESSMENT"


class SbomMonitoringStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class DependencyChangeOutcome(StrEnum):
    """Deterministic result of a dependency change check."""

    #: Head commit equals the commit the stored snapshot was generated at.
    UNCHANGED = "UNCHANGED"
    #: Commit moved but no dependency/build input path changed.
    NO_DEPENDENCY_CHANGE = "NO_DEPENDENCY_CHANGE"
    #: At least one dependency manifest/lockfile/build input changed.
    DEPENDENCY_CHANGED = "DEPENDENCY_CHANGED"
    #: No snapshot exists yet for the repository.
    NO_SNAPSHOT = "NO_SNAPSHOT"
    #: The provider could not be asked, or the diff base is unreachable.
    UNKNOWN = "UNKNOWN"
    #: The check itself failed (network, auth, provider error).
    FAILED = "FAILED"


class SbomChangeType(StrEnum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    VERSION_CHANGED = "VERSION_CHANGED"
    UNCHANGED = "UNCHANGED"


class SbomMonitoringTrigger(StrEnum):
    SCHEDULED = "SCHEDULED"
    WEBHOOK = "WEBHOOK"
    MANUAL = "MANUAL"
    INTEL_SYNC = "INTEL_SYNC"
    SBOM_UPDATE = "SBOM_UPDATE"
    FULL_SCAN = "FULL_SCAN"


# --------------------------------------------------------------------------- AI
class AIExecutionKind(StrEnum):
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    INVESTIGATION = "INVESTIGATION"
    REMEDIATION = "REMEDIATION"
    ASSISTANT = "ASSISTANT"
    #: Cross-domain investigation of a correlated incident (runtime/network/
    #: identity evidence), not a single finding.
    INCIDENT_INVESTIGATION = "INCIDENT_INVESTIGATION"


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


# ------------------------------------------------------- unified security events
class EventCategory(StrEnum):
    """Security domain an event belongs to.

    Domains stay separate in storage; the shared event model is what lets
    runtime, network and identity evidence be correlated into one incident.
    """

    RUNTIME = "RUNTIME"
    NETWORK = "NETWORK"
    IDENTITY = "IDENTITY"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    APPLICATION = "APPLICATION"
    DATA = "DATA"


EVENT_CATEGORIES = tuple(category.value for category in EventCategory)


class EventSource(StrEnum):
    FALCO = "FALCO"
    KUBERNETES_AUDIT = "KUBERNETES_AUDIT"
    NETWORK_SENSOR = "NETWORK_SENSOR"
    IDENTITY_PROVIDER = "IDENTITY_PROVIDER"
    APPLICATION_LOG = "APPLICATION_LOG"
    GENERIC = "GENERIC"


EVENT_SOURCES = tuple(source.value for source in EventSource)


class SecurityEventStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    CLOSED = "CLOSED"


EVENT_STATUSES = tuple(status.value for status in SecurityEventStatus)


class DetectionRuleType(StrEnum):
    #: Deterministic field conditions (process, file, network, identity).
    SIGNATURE = "SIGNATURE"
    #: Signature plus a count over a time window.
    THRESHOLD = "THRESHOLD"
    #: Statistical baseline comparison produced by the anomaly job.
    ANOMALY = "ANOMALY"


class DetectionRuleSource(StrEnum):
    BUILTIN = "BUILTIN"
    CUSTOM = "CUSTOM"


# ------------------------------------------------------------------- incidents
class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


INCIDENT_STATUSES = tuple(status.value for status in IncidentStatus)

ACTIVE_INCIDENT_STATUSES = (
    IncidentStatus.OPEN.value,
    IncidentStatus.TRIAGING.value,
    IncidentStatus.INVESTIGATING.value,
    IncidentStatus.CONTAINED.value,
)

#: Allowed transitions. Enforced in the service layer, like findings.
ALLOWED_INCIDENT_TRANSITIONS: dict[str, set[str]] = {
    IncidentStatus.OPEN.value: {
        IncidentStatus.TRIAGING.value,
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.TRIAGING.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.INVESTIGATING.value: {
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.TRIAGING.value,
    },
    IncidentStatus.CONTAINED.value: {
        IncidentStatus.RESOLVED.value,
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.RESOLVED.value: {
        IncidentStatus.CLOSED.value,
        IncidentStatus.OPEN.value,
    },
    IncidentStatus.CLOSED.value: {IncidentStatus.OPEN.value},
}


class IncidentPriority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


INCIDENT_PRIORITIES = tuple(priority.value for priority in IncidentPriority)


class IncidentEventKind(StrEnum):
    CREATED = "CREATED"
    EVENT_ATTACHED = "EVENT_ATTACHED"
    FINDING_ATTACHED = "FINDING_ATTACHED"
    STATUS_CHANGED = "STATUS_CHANGED"
    ASSIGNED = "ASSIGNED"
    NOTE = "NOTE"
    AI_INVESTIGATION = "AI_INVESTIGATION"
    REMEDIATION = "REMEDIATION"
    CORRELATION = "CORRELATION"


INCIDENT_EVENT_KINDS = tuple(kind.value for kind in IncidentEventKind)


# ------------------------------------------------------------- threat intel
class IndicatorType(StrEnum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    SHA256 = "SHA256"
    MD5 = "MD5"
    EMAIL = "EMAIL"


INDICATOR_TYPES = tuple(kind.value for kind in IndicatorType)


class IndicatorSource(StrEnum):
    MANUAL = "MANUAL"
    CSV_IMPORT = "CSV_IMPORT"
    EXTERNAL_FEED = "EXTERNAL_FEED"
    INTERNAL = "INTERNAL"


INDICATOR_SOURCES = tuple(source.value for source in IndicatorSource)


# ---------------------------------------------------------------- infrastructure
class InfraTargetKind(StrEnum):
    IAC_REPOSITORY = "IAC_REPOSITORY"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    KUBERNETES_MANIFEST = "KUBERNETES_MANIFEST"
    CLOUD_CONFIG = "CLOUD_CONFIG"


INFRA_TARGET_KINDS = tuple(kind.value for kind in InfraTargetKind)


class InfraScanStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


INFRA_SCAN_STATUSES = tuple(status.value for status in InfraScanStatus)

INFRA_ACTIVE_STATUSES = (InfraScanStatus.PENDING.value, InfraScanStatus.RUNNING.value)


class InfraScanner(StrEnum):
    TRIVY_CONFIG = "trivy-config"
    CHECKOV = "checkov"
    TRIVY_IMAGE = "trivy-image"


INFRA_SCANNERS = tuple(scanner.value for scanner in InfraScanner)


# ----------------------------------------------------------------------- audit
class AuditAction(StrEnum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    INGEST = "INGEST"
    EXECUTE = "EXECUTE"
    LOGIN = "LOGIN"


AUDIT_ACTIONS = tuple(action.value for action in AuditAction)
