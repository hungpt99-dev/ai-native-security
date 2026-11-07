export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";

export type FindingStatus =
  | "OPEN"
  | "CONFIRMED"
  | "FALSE_POSITIVE"
  | "ACCEPTED_RISK"
  | "RESOLVED";

export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELED";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface Asset {
  id: string;
  name: string;
  repo_url: string;
  provider: string;
  default_branch: string;
  description: string | null;
  has_credential: boolean;
  credential_hint: string | null;
  monitoring_enabled: boolean;
  scan_interval_minutes: number | null;
  last_scan_at: string | null;
  last_scan_status: ScanStatus | null;
  created_at: string;
  updated_at: string;
}

export interface ScannerExecution {
  id: string;
  scanner: string;
  status: string;
  version: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  exit_code: number | null;
  result_count: number;
  command: { argv?: string[] } | null;
  stdout_excerpt: string | null;
  stderr_excerpt: string | null;
  error_message: string | null;
}

export interface Scan {
  id: string;
  asset_id: string;
  status: ScanStatus;
  trigger: string;
  branch: string | null;
  commit_sha: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  unknown_count: number;
  new_findings: number;
  resolved_findings: number;
  error_message: string | null;
  created_at: string;
  asset_name?: string | null;
  asset_repo_url?: string | null;
  executions?: ScannerExecution[];
}

export interface Finding {
  id: string;
  asset_id: string;
  first_scan_id: string | null;
  last_scan_id: string | null;
  scanner: string;
  rule_id: string;
  title: string;
  description: string | null;
  category: string | null;
  severity: Severity;
  file_path: string | null;
  line_number: number | null;
  package_name: string | null;
  package_version: string | null;
  purl: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  status: FindingStatus;
  discovery_source: string;
  metadata: Record<string, unknown>;
  first_detected_at: string;
  last_detected_at: string;
  resolved_at: string | null;
  asset_name?: string | null;
  asset_repo_url?: string | null;
  history?: FindingHistoryEntry[];
}

export interface FindingHistoryEntry {
  id: string;
  event: string;
  from_status: string | null;
  to_status: string | null;
  actor: string;
  note: string | null;
  scan_id: string | null;
  created_at: string;
}

export interface Sbom {
  id: string;
  asset_id: string;
  scan_id: string | null;
  format: string;
  spec_version: string | null;
  tool_name: string;
  tool_version: string | null;
  sha256: string;
  size_bytes: number;
  package_count: number;
  created_at: string;
  commit_sha: string | null;
  branch: string | null;
  dependency_fingerprint: string | null;
  manifest_fingerprint: string | null;
  artifact_digest: string | null;
  creation_reason: string | null;
  generation_status: string | null;
  previous_snapshot_id: string | null;
  generated_at: string | null;
  direct_package_count: number | null;
  transitive_package_count: number | null;
}

export type SbomFreshness = "MISSING" | "CURRENT" | "STALE" | "PENDING" | "FAILED" | "UNKNOWN";

export type MonitoringRunKind =
  | "DEPENDENCY_CHECK"
  | "SBOM_GENERATION"
  | "VULNERABILITY_REASSESSMENT";

export type MonitoringRunStatus = "RUNNING" | "SUCCEEDED" | "PARTIAL" | "FAILED" | "SKIPPED";

export interface MonitoringRun {
  id: string;
  asset_id: string;
  sbom_id: string | null;
  job_id: string | null;
  kind: MonitoringRunKind;
  trigger: string;
  status: MonitoringRunStatus;
  outcome: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  head_commit_sha: string | null;
  previous_commit_sha: string | null;
  branch: string | null;
  dependency_fingerprint: string | null;
  previous_dependency_fingerprint: string | null;
  components_evaluated: number;
  findings_created: number;
  findings_updated: number;
  findings_resolved: number;
  new_kev_findings: number;
  failure_count: number;
  skipped_reason: string | null;
  error_message: string | null;
  metrics: Record<string, unknown>;
}

export interface SbomSnapshotSummary {
  id: string;
  created_at: string | null;
  generated_at: string | null;
  commit_sha: string | null;
  branch: string | null;
  dependency_fingerprint: string | null;
  manifest_fingerprint: string | null;
  artifact_digest: string | null;
  sha256: string;
  creation_reason: string;
  generation_status: string;
  package_count: number;
  direct_package_count: number | null;
  transitive_package_count: number | null;
  previous_snapshot_id: string | null;
  size_bytes: number;
  format: string;
}

export interface SbomStatus {
  asset_id: string;
  monitoring_enabled: boolean;
  sbom_monitoring_enabled: boolean;
  monitoring_status: "HEALTHY" | "DEGRADED" | "UNKNOWN" | "RUNNING" | "DISABLED";
  freshness: SbomFreshness;
  freshness_detail: string;
  latest_snapshot: SbomSnapshotSummary | null;
  vulnerable_components: number;
  pending: {
    dependency_check: boolean;
    sbom_generation: boolean;
    reassessment: boolean;
    dependency_change_pending: boolean;
  };
  last_dependency_check: MonitoringRun | null;
  last_generation: MonitoringRun | null;
  last_reassessment: MonitoringRun | null;
  next_dependency_check: string | null;
  next_reassessment: string | null;
  failed_evaluations_7d: number;
  new_findings_since_last_evaluation: number;
  new_kev_since_last_evaluation: number;
}

export type SbomChangeType = "ADDED" | "REMOVED" | "VERSION_CHANGED" | "UNCHANGED";

export interface ComponentChange {
  change: SbomChangeType;
  identity: string;
  identity_basis: string;
  name: string;
  ecosystem: string | null;
  purl: string | null;
  version_before: string | null;
  version_after: string | null;
  is_direct_before: boolean | null;
  is_direct_after: boolean | null;
}

export interface SbomDiff {
  previous_sbom_id: string | null;
  current_sbom_id: string | null;
  added: number;
  removed: number;
  version_changed: number;
  unchanged: number;
  changed: number;
  total_previous: number;
  total_current: number;
  items: ComponentChange[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface MonitoringSummary {
  window_days: number;
  dependency_checks: number;
  dependency_changes_detected: number;
  dependency_checks_unchanged: number;
  dependency_checks_unknown: number;
  sbom_generations: number;
  sbom_generations_skipped_unchanged: number;
  reassessments: number;
  reassessment_failures: number;
  components_evaluated: number;
  findings_created: number;
  findings_updated: number;
  findings_resolved: number;
  findings_reopened: number;
  new_kev_findings: number;
  avg_dependency_check_ms: number | null;
  avg_generation_ms: number | null;
  avg_reassessment_ms: number | null;
  estimated_full_scans_avoided: number;
  estimated_repository_checkouts_avoided: number;
  estimated_scanner_executions_avoided: number;
  estimate_basis: string;
}

export interface SbomPackage {
  id: string;
  name: string;
  version: string;
  ecosystem: string | null;
  purl: string | null;
  license: string | null;
  source_type: string | null;
  cpe: string | null;
}

export interface Vulnerability {
  id: string;
  source: string;
  source_id: string;
  cve_id: string | null;
  osv_id: string | null;
  summary: string | null;
  severity: Severity;
  cvss_score: number | null;
  is_kev: boolean;
  published_at: string | null;
  modified_at: string | null;
  description?: string | null;
  cvss_vector?: string | null;
  kev_due_date?: string | null;
  kev_required_action?: string | null;
  references?: { id: string; url: string; ref_type: string | null; source: string | null }[];
  affected_packages?: {
    id: string;
    ecosystem: string;
    package_name: string;
    purl: string | null;
    affected_versions: string[];
    fixed_versions: string[];
  }[];
}

export interface DashboardSummary {
  assets: { total: number; monitored: number };
  findings: {
    total: number;
    active: number;
    resolved: number;
    critical_open: number;
    high_open: number;
    kev: number;
    by_severity: { severity: Severity; total: number }[];
    by_scanner: { scanner: string; total: number }[];
    by_status: { status: string; total: number }[];
  };
  scans: {
    last_24h: number;
    failed_last_24h: number;
    active: number;
    recent: {
      id: string;
      asset_id: string;
      asset_name: string | null;
      status: ScanStatus;
      trigger: string;
      created_at: string;
      total_findings: number;
    }[];
  };
  failing_assets: { id: string; name: string; repo_url: string; last_scan_at: string | null }[];
  intelligence: { vulnerabilities: number; kev: number };
}

export interface Job {
  id: string;
  kind: string;
  status: string;
  payload: Record<string, unknown>;
  attempts: number;
  max_attempts: number;
  run_after: string;
  finished_at: string | null;
  last_error: string | null;
  created_at: string;
}

export interface Schedule {
  id: string;
  name: string;
  kind: string;
  payload: Record<string, unknown>;
  interval_seconds: number;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
}

export interface SystemInfo {
  name: string;
  version: string;
  environment: string;
  auth_enabled: boolean;
  uptime_seconds: number;
  scanners_enabled: string[];
  storage_backend: string;
}

export interface ScannerStatus {
  scanner: string;
  enabled: boolean;
  available: boolean;
  version: string | null;
  error: string | null;
}

export interface IntelligenceStats {
  total: number;
  kev: number;
  by_source: Record<string, number>;
  by_severity: Record<string, number>;
  last_sync: Record<string, string | null>;
}

// -------------------------------------------------------------------- AI layer
export type AiCapabilities = {
  structured_output: boolean;
  json_schema: boolean;
  max_output_tokens: number;
  reports_cost: boolean;
};

export type AiHealth = {
  enabled: boolean;
  provider: string;
  model: string;
  configured: boolean;
  budget_usd_per_day: number;
  capabilities: AiCapabilities;
  budget?: {
    cost_usd_today: number;
    input_tokens_today: number;
    output_tokens_today: number;
    executions_today: number;
  };
  prompts?: number;
};

export type EvidenceItem = {
  key: string;
  kind: string;
  source: string;
  locator: string | null;
  sha256: string;
  cited?: boolean;
  excerpt?: string | null;
};

export type MissingInformation = {
  code: string;
  message: string;
  affects?: string[];
};

export type SecurityContextPayload = {
  snapshot_id: string;
  finding_id: string;
  context_version: string;
  evidence_hash: string;
  missing_information: MissingInformation[];
  payload: Record<string, unknown>;
  created_at: string | null;
  evidence_count?: number;
};

export type RiskAssessment = {
  id: string;
  finding_id: string;
  asset_id: string;
  risk_level: string;
  deterministic_score: number;
  ai_risk_score: number | null;
  ai_risk_level: string | null;
  final_score: number;
  confidence: number | null;
  deterministic_only: boolean;
  requires_human_review: boolean;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  summary: string | null;
  impact_analysis: string | null;
  exploitability_analysis: string | null;
  affected_components: string[];
  signals: Array<{
    key: string;
    label: string;
    value: unknown;
    normalized: number;
    weight: number;
    contribution: number;
    known: boolean;
    source: string;
    note?: string;
  }>;
  evidence: EvidenceItem[];
  missing_information: MissingInformation[];
  recommended_actions: string[];
  model: string | null;
  prompt_version: string | null;
  created_at: string | null;
};

export type InvestigationReport = {
  id: string;
  finding_id: string;
  status: string;
  summary: string | null;
  impact_analysis: string | null;
  exploitability_analysis: string | null;
  confidence: number | null;
  answers: Record<string, string>;
  evidence_ids: string[];
  missing_information: MissingInformation[];
  next_steps: string[];
  workflow: { name: string; version: string };
  model: string;
  prompt_version: string;
  error_code: string | null;
  error_message: string | null;
  duration_ms: number | null;
  created_at: string | null;
  evidence: EvidenceItem[];
};

export type RemediationRecommendation = {
  id: string;
  finding_id: string;
  asset_id: string;
  strategy: string;
  status: string;
  summary: string | null;
  reasoning: string | null;
  target_package: string | null;
  current_version: string | null;
  recommended_version: string | null;
  version_verified: boolean;
  patch: string | null;
  patch_format: string | null;
  changes: Array<{ file?: string; description?: string }>;
  breaking_change_risks: string[];
  recommended_tests: string[];
  expected_security_improvement: string | null;
  missing_information: MissingInformation[];
  requires_human_approval: boolean;
  approved_by: string | null;
  approved_at: string | null;
  rejected_reason: string | null;
  model: string | null;
  created_at: string | null;
  verifications?: RemediationVerification[];
};

export type RemediationVerification = {
  id: string;
  recommendation_id: string;
  finding_id: string;
  status: string;
  before_version: string | null;
  after_version: string | null;
  finding_present_after: boolean | null;
  package_present_after: boolean | null;
  new_findings_count: number | null;
  policy_result: Record<string, unknown>;
  evidence: Record<string, unknown>;
  notes: string | null;
  ai_explanation: string | null;
  verification_scan_id: string | null;
  verified_at: string | null;
  created_at: string | null;
};

export type AiOverview = {
  provider: AiHealth;
  budget: { cost_usd_today: number; input_tokens_today: number; output_tokens_today: number; executions_today: number };
  top_risk_assets: Array<{
    asset_id: string;
    name: string;
    repo_url: string;
    highest_final_score: number;
    assessments: number;
  }>;
  critical_findings: Array<{
    assessment_id: string;
    finding_id: string;
    asset_id: string;
    asset_name: string;
    title: string;
    severity: string;
    risk_level: string;
    final_score: number;
    confidence: number | null;
    deterministic_only: boolean;
    requires_human_review: boolean;
    created_at: string | null;
  }>;
  needs_review: number;
  remediation_pending: number;
  unverified_proposals: number;
};

export type AssistantReply = {
  conversation_id: string;
  answer: string;
  tool_results: Array<{ tool: string; count: number; rows: unknown; error: string | null }>;
  cited_finding_ids: string[];
  cited_asset_ids: string[];
  data_gaps: string[];
  executions: string[];
  model: string;
};

export type AiExecution = {
  id: string;
  kind: string;
  status: string;
  provider: string;
  model: string;
  prompt_id: string;
  prompt_version: string;
  finding_id: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  cost_usd: number | null;
  duration_ms: number | null;
  attempts: number;
  error_code: string | null;
  started_at: string | null;
  finished_at: string | null;
};

/* ------------------------------------------------------------------ platform */

export type AssetKind =
  | "REPOSITORY"
  | "CONTAINER_IMAGE"
  | "HOST"
  | "CLOUD_RESOURCE"
  | "KUBERNETES_WORKLOAD"
  | "API_SERVICE";

export type EventCategory =
  | "RUNTIME"
  | "NETWORK"
  | "IDENTITY"
  | "INFRASTRUCTURE"
  | "APPLICATION"
  | "DATA";

export interface SecurityEvent {
  id: string;
  category: EventCategory;
  source: string;
  source_event_id: string | null;
  event_type: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: "OPEN" | "ACKNOWLEDGED" | "CLOSED";
  asset_id: string | null;
  incident_id: string | null;
  rule_slug: string | null;
  rule_version: number | null;
  risk_score: number | null;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  acknowledged_at: string | null;
  closed_at: string | null;
  normalized: Record<string, unknown>;
  indicators: Array<{ type: string; value: string }>;
  enrichment: {
    asset?: { resolved?: boolean; match?: string; external_ref?: string };
    threat_matches?: Array<{ type: string; value: string; source: string; confidence: number }>;
    matched_rules?: Array<{ slug: string; severity: string; version: number }>;
    threshold?: { rule: string; count: number; window_seconds: number };
    incident?: { id: string; priority: string };
    raw_truncated?: boolean;
  };
  created_at: string;
  raw?: Record<string, unknown>;
}

export interface DetectionRule {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  category: string;
  severity: Severity;
  rule_type: "SIGNATURE" | "THRESHOLD" | "ANOMALY";
  source: "BUILTIN" | "CUSTOM";
  enabled: boolean;
  version: number;
  conditions: Record<string, unknown>;
  threshold: Record<string, unknown> | null;
  create_incident: boolean;
  incident_priority: string | null;
  match_count: number;
  last_matched_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface EventSummary {
  window_hours: number;
  total: number;
  open: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  last_event_at: string | null;
  per_hour: Array<{ hour: string; count: number }>;
}

export type IncidentStatus =
  | "OPEN"
  | "TRIAGING"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED"
  | "CLOSED";

export interface Incident {
  id: string;
  title: string;
  summary: string | null;
  severity: Severity;
  priority: "P1" | "P2" | "P3" | "P4";
  status: IncidentStatus;
  category: EventCategory | null;
  asset_id: string | null;
  correlation_key: string;
  detection_rule_slug: string | null;
  risk_score: number;
  event_count: number;
  finding_count: number;
  assigned_to: string | null;
  opened_at: string;
  acknowledged_at: string | null;
  contained_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface IncidentTimelineEntry {
  id: string;
  kind: string;
  message: string;
  actor: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface IncidentDetail {
  incident: Incident;
  asset: {
    id: string;
    name: string;
    kind: AssetKind;
    repo_url: string | null;
    external_ref: string | null;
  } | null;
  events: SecurityEvent[];
  findings: Array<{
    id: string;
    title: string;
    severity: Severity;
    status: string;
    cve_id: string | null;
    package_name: string | null;
    file_path: string | null;
    asset_id: string;
  }>;
  timeline: IncidentTimelineEntry[];
}

export interface IncidentSummary {
  active: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  top_open: Incident[];
}

export interface IncidentInvestigation {
  id: string;
  incident_id: string;
  status: string;
  summary: string;
  confidence: number | null;
  evidence: Array<{ key: string; note: string }>;
  missing_information: Array<{ code: string; message: string }>;
  next_actions: string[];
  attack_steps: Array<{ order: number; description: string; evidence: string[] }>;
  model: string;
  prompt_id: string;
  prompt_version: string;
  ai_execution_id: string | null;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
}

export interface MonitoringComponent {
  status: "HEALTHY" | "DEGRADED" | "UNKNOWN" | "DISABLED";
  detail: Record<string, unknown>;
  checked_at: string;
}

export interface MonitoringHealth {
  status: string;
  components: Record<string, MonitoringComponent>;
  checked_at: string;
}

export interface PlatformOverview {
  assets: { total: number; by_kind: Record<string, number> };
  findings: { active: number; by_severity: Record<string, number> };
  incidents: { active: number; top: Incident[] };
  events: { last_24h: number; highest_risk: SecurityEvent[] };
  health: string;
}

export interface InfrastructureScan {
  id: string;
  asset_id: string | null;
  target_kind: string;
  target_ref: string;
  scanner: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "SKIPPED";
  triggered_by: string;
  requested_by: string | null;
  commit_sha: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  error_message: string | null;
  scanner_version: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
}

export interface InfraAsset {
  id: string;
  name: string;
  kind: AssetKind;
  external_ref: string | null;
  parent_asset_id: string | null;
  repo_url: string | null;
  description: string | null;
  monitoring_enabled: boolean;
  last_infra_scan_at: string | null;
  last_infra_scan_status: string | null;
  created_at: string;
}

export interface InfrastructureSummary {
  enabled: boolean;
  active: number;
  by_target_kind: Record<string, number>;
  scans_with_findings: Record<string, number>;
  open_findings_by_severity: Record<string, number>;
  last_scan_at: string | null;
  scanners: Array<{
    scanner: string;
    target_kind: string;
    available: boolean;
    error: string | null;
  }>;
}

export interface ThreatIndicator {
  id: string;
  indicator_type: string;
  value: string;
  source: string;
  source_ref: string | null;
  severity: Severity;
  confidence: number;
  description: string | null;
  tags: string[];
  active: boolean;
  first_seen_at: string | null;
  last_seen_at: string | null;
  expires_at: string | null;
  ingested_at: string;
  created_at: string;
}

export interface AuditEntry {
  id: string;
  created_at: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  status_code: number | null;
  request_id: string | null;
  ip_address: string | null;
  detail: Record<string, unknown>;
}
