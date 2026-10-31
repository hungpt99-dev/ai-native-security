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
