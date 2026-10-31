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
