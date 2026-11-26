// Types mirror the backend contract in BACKEND_CONTEXT.md and Backend/app/schemas.
// final_severity is always server-computed and read-only.

export type ISODate = string;

export type Role = "admin" | "assessor";

export type AssessmentStatus =
  | "draft"
  | "ready"
  | "in_progress"
  | "in_review"
  | "completed"
  | "archived";

export type ScopeKind = "host" | "ip" | "cidr" | "url_prefix" | "port";

export type ScanTool =
  | "nmap"
  | "zap"
  | "dig"
  | "whois"
  | "whatweb"
  | "curl"
  | "http_checks";

export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type NmapProfile = "quick" | "standard" | "full_tcp";
export type ZapProfile = "baseline" | "active_limited";
export type HttpCheckProfile =
  | "config_baseline"
  | "session"
  | "access_control"
  | "auth_limited";

export type FindingSource =
  | "nmap"
  | "zap"
  | "whatweb"
  | "http_checks"
  | "manual";

export type FindingCategory =
  | "injection"
  | "authentication"
  | "session_management"
  | "security_configuration"
  | "information_disclosure"
  | "access_control"
  | "exposed_files"
  | "business_logic"
  | "uncategorized";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type VerificationStatus =
  | "pending"
  | "confirmed"
  | "false_positive"
  | "needs_retest";

export type VerificationDecision = Exclude<VerificationStatus, "pending">;

export type EvidenceType = "tool_output" | "http_exchange" | "note" | "file";

export type AIFunction = "interpret" | "remediate" | "summary";

export type AIAnalysisStatus = "success" | "failed" | "invalid_output";

export type SummaryStatus = "draft" | "approved" | "superseded";

export type AIJobStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type ReportFormat = "pdf" | "html";
export type ReportStatus = "pending" | "ready" | "failed";

export type AuditOutcome = "allowed" | "denied";

export type FindingSortField =
  | "created_at"
  | "last_seen_at"
  | "severity"
  | "title";

export type SortOrder = "asc" | "desc";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown | null;
  };
}

export interface ValidationIssue {
  loc: (string | number)[];
  msg: string;
  type: string;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

export interface DependencyCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface DependenciesResponse {
  status: string;
  dependencies: DependencyCheck[];
}

export interface UserSummary {
  id: number;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
}

export interface UserOut extends UserSummary {
  created_at: ISODate;
  updated_at: ISODate;
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  user: UserSummary;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface UserCreate {
  email: string;
  full_name: string;
  password: string;
  role?: Role;
}

export interface UserUpdate {
  full_name?: string;
  role?: Role;
  is_active?: boolean;
  password?: string;
}

export interface AssessmentOut {
  id: number;
  name: string;
  description: string | null;
  target_name: string;
  target_base_url: string | null;
  target_description: string | null;
  owner_name: string;
  authorization_reference: string;
  authorization_confirmed: boolean;
  authorization_confirmed_by: number | null;
  authorization_confirmed_at: ISODate | null;
  hosting_environment: string | null;
  selected_categories: FindingCategory[];
  status: AssessmentStatus;
  created_by: number;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface AssessmentCreate {
  name: string;
  description?: string | null;
  target_name: string;
  target_base_url?: string | null;
  target_description?: string | null;
  owner_name: string;
  authorization_reference: string;
  hosting_environment?: string | null;
  selected_categories?: FindingCategory[];
}

export interface AssessmentUpdate {
  name?: string;
  description?: string | null;
  target_name?: string;
  target_base_url?: string | null;
  target_description?: string | null;
  owner_name?: string;
  authorization_reference?: string;
  hosting_environment?: string | null;
  selected_categories?: FindingCategory[] | null;
  status?: AssessmentStatus | null;
}

export interface ScopeItemOut {
  id: number;
  assessment_id: number;
  kind: ScopeKind;
  value: string;
  in_scope: boolean;
  note: string | null;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface ScopeItemCreate {
  kind: ScopeKind;
  value: string;
  in_scope?: boolean;
  note?: string | null;
}

export interface ScopeCheckRequest {
  target: string;
  tool: ScanTool;
  ports?: number[];
}

export interface ScopeCheckResponse {
  allowed: boolean;
  reasons: string[];
  target: Record<string, unknown> | null;
  resolved_ips: string[];
  matched_rules: string[];
  zap_context_include: string[];
  zap_context_exclude: string[];
}

export interface ScanOut {
  id: number;
  assessment_id: number;
  tool: ScanTool;
  profile: string;
  target: string;
  status: ScanStatus;
  progress: number;
  started_at: ISODate | null;
  finished_at: ISODate | null;
  duration_seconds: number | null;
  error: string | null;
  raw_output_sha256: string | null;
  has_raw_output: boolean;
  tool_version: string | null;
  parameters: Record<string, unknown>;
  created_by: number;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface ScanCreate {
  tool: ScanTool;
  profile: string;
  target: string;
  ports?: number[];
  confirm_lockout_test?: boolean;
}

export interface ScanQueuedOut {
  scan_id: number;
  status: ScanStatus;
}

export interface ReconOut {
  assessment_id: number;
  generated_at: ISODate;
  totals: {
    scans: number;
    hosts: number;
    hosts_up: number;
    open_ports: number;
  };
  scans: Array<{
    id: number;
    profile: string;
    target: string;
    status: string;
    progress: number;
    started_at: ISODate | null;
    finished_at: ISODate | null;
    duration_seconds: number | null;
    tool_version: string | null;
    raw_output_sha256: string | null;
    error: string | null;
    parse_error: string | null;
  }>;
  hosts: Array<{
    address: string;
    address_type: string;
    status: string;
    hostnames: string[];
    os_matches: string[];
    ports: Array<{
      port: number;
      protocol: string;
      state: string;
      reason: string | null;
      service: {
        name: string | null;
        product: string | null;
        version: string | null;
        extrainfo: string | null;
        tunnel: string | null;
      } | null;
    }>;
    scan_ids: number[];
  }>;
  dns: Array<{
    scan_id: number;
    target: string;
    records: Record<string, string[]>;
    record_count: number;
  }>;
  whois: Array<{
    scan_id: number;
    target: string;
    skipped: boolean;
    note: string | null;
    fields: Record<string, string>;
  }>;
  technologies: Array<{
    scan_id: number;
    target: string;
    status_code: number | null;
    targets: string[];
    technologies: Record<string, string[]>;
  }>;
  http: Array<{
    scan_id: number;
    target: string;
    status_code: number | null;
    content_type: string | null;
    header_count: number;
    body_bytes: number;
    location: string | null;
  }>;
}

export interface FindingOut {
  id: number;
  assessment_id: number;
  scan_id: number | null;
  source: FindingSource;
  title: string;
  description: string | null;
  category: FindingCategory;
  owasp_category: string | null;
  cwe: string | null;
  affected_url: string | null;
  http_method: string | null;
  parameter: string | null;
  tool_severity: Severity | null;
  ai_suggested_severity: Severity | null;
  final_severity: Severity | null;
  likelihood: number | null;
  impact: number | null;
  tool_confidence: string | null;
  verification_status: VerificationStatus;
  rejection_reason: string | null;
  verified_by: number | null;
  verified_at: ISODate | null;
  final_remediation: string | null;
  first_seen_at: ISODate;
  last_seen_at: ISODate;
  seen_count: number;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface FindingDetailOut extends FindingOut {
  raw: Record<string, unknown>;
}

export interface ManualFindingCreate {
  title: string;
  description?: string | null;
  category?: FindingCategory;
  severity: Severity;
  affected_url?: string | null;
  http_method?: string | null;
  parameter?: string | null;
  cwe?: string | null;
  owasp_category?: string | null;
}

export interface FindingVerify {
  decision: VerificationDecision;
  likelihood?: number | null;
  impact?: number | null;
  final_remediation?: string | null;
  reason?: string | null;
}

export interface FindingFilters {
  severity?: Severity;
  status?: VerificationStatus;
  category?: FindingCategory;
  source?: FindingSource;
  q?: string;
  sort?: FindingSortField;
  order?: SortOrder;
  page?: number;
  page_size?: number;
}

export interface EvidenceOut {
  id: number;
  finding_id: number | null;
  scan_id: number | null;
  type: EvidenceType;
  content: string | null;
  filename: string | null;
  has_file: boolean;
  download_url: string | null;
  sha256: string | null;
  created_by: number | null;
  created_at: ISODate;
}

export interface AIAnalysisOut {
  id: number;
  finding_id: number | null;
  assessment_id: number | null;
  function: AIFunction;
  provider: string;
  model: string;
  prompt_version: string;
  input_hash: string;
  sanitized_input: string;
  output: Record<string, unknown> | null;
  status: AIAnalysisStatus;
  error: string | null;
  latency_ms: number | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  redaction_report: Record<string, number> | null;
  attempts: Array<{
    provider: string;
    model: string | null;
    outcome: "success" | "error" | "circuit_open";
    latency_ms: number;
    error_class: string | null;
  }> | null;
  created_at: ISODate;
}

/** Real backend shape: POST /findings/{id}/analyze returns both analyses. */
export interface FindingAnalysisOut {
  finding_id: number;
  analyses: AIAnalysisOut[];
}

export interface SummaryOut {
  id: number;
  assessment_id: number;
  status: SummaryStatus;
  provider: string;
  model: string;
  output: Record<string, unknown> | null;
  edited_text: string | null;
  text: string;
  overall_risk: Severity | null;
  approved_by: number | null;
  approved_at: ISODate | null;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface SummaryBundle {
  latest: SummaryOut | null;
  history: SummaryOut[];
}

export interface BulkAnalyzeRequest {
  min_severity?: Severity | null;
  only_unanalyzed?: boolean;
  force?: boolean;
}

export interface BulkAnalyzeQueued {
  job_id: number;
  assessment_id: number;
  status: AIJobStatus;
  total: number;
}

export interface AIJobOut {
  id: number;
  assessment_id: number;
  status: AIJobStatus;
  total: number;
  processed: number;
  failed: number;
  error: string | null;
  created_at: ISODate;
  started_at: ISODate | null;
  finished_at: ISODate | null;
}

export interface AIStatusOut {
  assessment_id: number;
  total_findings: number;
  findings_with_interpretation: number;
  findings_with_remediation: number;
  pending_findings: number;
  last_analyzed_at: ISODate | null;
  job: AIJobOut | null;
}

export interface ReportOut {
  id: number;
  assessment_id: number;
  format: ReportFormat;
  status: ReportStatus;
  sha256: string | null;
  generated_by: number;
  summary_counts: Record<string, unknown>;
  error: string | null;
  has_file: boolean;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface AuditLogOut {
  id: number;
  assessment_id: number | null;
  user_id: number | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  details: Record<string, unknown>;
  created_at: ISODate;
}

export interface AuditFilters {
  action?: string;
  entity_type?: string;
  user_id?: number;
  outcome?: AuditOutcome;
  from?: string;
  to?: string;
  page?: number;
  page_size?: number;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface VerificationCounts {
  pending: number;
  confirmed: number;
  false_positive: number;
  needs_retest: number;
}

export interface DashboardOut {
  assessment_id: number;
  generated_at: ISODate;
  total_findings: number;
  severity_confirmed: SeverityCounts;
  severity_unverified: {
    ai: SeverityCounts;
    tool: SeverityCounts;
    total: SeverityCounts;
  };
  severity_basis: string;
  status_counts: VerificationCounts;
  category_counts: {
    confirmed: Record<string, number>;
    unverified: Record<string, number>;
  };
  scan_history: Array<{
    id: number;
    tool: string;
    profile: string;
    status: string;
    started_at: ISODate | null;
    finished_at: ISODate | null;
    duration_seconds: number | null;
  }>;
  ai_coverage: {
    analyzed: number;
    total: number;
    coverage_percent: number;
  };
  ai_summary: SummaryOut | null;
  top_confirmed_findings: Array<{
    id: number;
    title: string;
    final_severity: string | null;
    category: string;
    affected_url: string | null;
  }>;
  last_updated_at: ISODate | null;
}

export interface LoginSpec {
  url: string;
  method: "POST";
  content_type: "form" | "json";
  username_field: string;
  password_field: string;
  success_status: number | null;
  success_redirect: string | null;
  success_regex: string | null;
  csrf_regex: string | null;
}

export interface AccessRule {
  path: string;
  method: "GET" | "HEAD" | "OPTIONS";
  allowed_roles: string[];
  id_template: boolean;
  sample_ids: string[];
}

export interface HttpCheckLimits {
  max_requests: number;
  max_rps: number;
  max_login_attempts: number;
  min_login_interval_seconds: number;
  max_redirects: number;
}

export interface HttpCheckConfigIn {
  login: LoginSpec | null;
  access_rules: AccessRule[];
  roles: string[];
  limits: HttpCheckLimits;
}

export interface HttpCheckConfigOut extends HttpCheckConfigIn {
  id: number;
  assessment_id: number;
  updated_by: number | null;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface TestAccountOut {
  id: number;
  assessment_id: number;
  role: string;
  username: string;
  created_at: ISODate;
}

export interface TestAccountCreate {
  role: string;
  username: string;
  password: string;
}

export interface SeverityMatrixOut {
  likelihood: {
    minimum: number;
    maximum: number;
    labels: Record<string, string>;
  };
  impact: {
    minimum: number;
    maximum: number;
    labels: Record<string, string>;
  };
  thresholds: Array<{
    min_score: number;
    max_score: number;
    severity: Severity;
  }>;
  formula: string;
  final_severity_source: string;
}

export const SEVERITIES: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export const FINDING_CATEGORIES: FindingCategory[] = [
  "injection",
  "authentication",
  "session_management",
  "security_configuration",
  "information_disclosure",
  "access_control",
  "exposed_files",
  "business_logic",
  "uncategorized",
];

export const ASSESSMENT_STATUSES: AssessmentStatus[] = [
  "draft",
  "ready",
  "in_progress",
  "in_review",
  "completed",
  "archived",
];

export const VERIFICATION_STATUSES: VerificationStatus[] = [
  "pending",
  "confirmed",
  "false_positive",
  "needs_retest",
];

export const FINDING_SOURCES: FindingSource[] = [
  "nmap",
  "zap",
  "whatweb",
  "http_checks",
  "manual",
];

export const SCAN_TOOLS: ScanTool[] = [
  "nmap",
  "zap",
  "dig",
  "whois",
  "whatweb",
  "curl",
  "http_checks",
];

export const SCAN_STATUSES: ScanStatus[] = [
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
];

export const SCAN_PROFILES: Record<ScanTool, string[]> = {
  nmap: ["quick", "standard", "full_tcp"],
  zap: ["baseline", "active_limited"],
  dig: ["default"],
  whois: ["default"],
  whatweb: ["default"],
  curl: ["default"],
  http_checks: [
    "config_baseline",
    "session",
    "access_control",
    "auth_limited",
  ],
};
