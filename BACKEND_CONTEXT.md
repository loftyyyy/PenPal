# PenPal Backend Context

Frontend integration contract for the PenPal backend. Source of truth for code:
`Backend/app`; generated schema: `docs/openapi.json`; this file describes the live
contract as of 2026-11-25.

Backend is complete for the current phase. Frontend is not built.

---

## 1. Base configuration

| Item | Value |
|---|---|
| API base URL (local) | `http://localhost:8000/api/v1` |
| API base URL (deployed) | `https://<backend-host>/api/v1` |
| OpenAPI JSON | `GET /openapi.json` in development only |
| Swagger UI | `GET /docs` in development only |
| Auth scheme | `Authorization: Bearer <JWT>` |
| Default CORS origin | `http://localhost:5173` (`CORS_ORIGINS`, comma-separated) |
| CORS allowed methods | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` |
| CORS allowed headers | `Authorization`, `Content-Type`, `X-Request-ID` |
| CORS exposed headers | `X-Request-ID`, `Content-Disposition` |
| Content type | `application/json` except evidence upload and file downloads |
| Datetime format | ISO 8601 UTC, e.g. `2026-11-25T12:34:56Z` |
| IDs | integers |
| Server | one backend process, in-process scan and AI jobs |

Production disables `/docs`, `/redoc` and `/openapi.json`. Every API response sends
`Cache-Control: no-store` and a restrictive CSP. `X-Request-ID` is present on responses;
send your own to correlate logs.

### Required frontend setup

```ts
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";
```

Store the access token in memory or secure storage. There is no refresh token endpoint.
On `401`, send the user to login again.

---

## 2. Architecture

```text
React frontend
   |
   v
FastAPI routers (/api/v1)
   |
   +-- auth/users -> JWT, argon2, login throttle
   +-- assessments/scope -> scope guard, authorization
   +-- scans -> ScanManager -> Nmap / ZAP / dig / whois / WhatWeb / curl / http_checks
   +-- findings -> normalizer, manual findings, evidence, verification
   +-- AI -> sanitizer -> NVIDIA primary -> NVIDIA fallback -> ai_analyses
   +-- summaries -> draft/edit/approve workflow
   +-- dashboard/audit/reports -> read models and Jinja2/WeasyPrint
   |
   v
PostgreSQL (SQLite in tests)
```

- Scans and bulk AI are asynchronous. API returns immediately; client polls.
- Reports are generated synchronously and stored under `DATA_DIR/reports/`.
- Raw scan output and uploaded evidence are stored under `DATA_DIR`.
- No WebSockets, no webhooks, no server-sent events. Polling only.

---

## 3. Authentication and authorization

### Flow

1. `POST /auth/login` with email and password.
2. Response contains `access_token`, `token_type`, `expires_in` seconds and user.
3. Send `Authorization: Bearer <token>` on every protected request.
4. `GET /auth/me` returns the current user.
5. No refresh token. Re-login when expired.

JWT is HS256, default lifetime 60 minutes. Tokens are invalid after expiry, user
deactivation or password change.

### Roles

| Role | Capabilities |
|---|---|
| `admin` | Everything, including user management |
| `assessor` | All assessment work: assessments, scope, scans, findings, AI, dashboard, reports, audit |

Any authenticated assessor may access any assessment. There is no per-assessment
ownership restriction, no customer role, no SSO.

### Login throttling

Failed logins are limited in memory by email + client IP. Defaults:

- `LOGIN_MAX_ATTEMPTS=5`
- `LOGIN_LOCKOUT_SECONDS=300`

Exceeded limit returns `429` with `Retry-After` and
`{"error":{"code":"too_many_attempts",...}}`. Restart clears the limiter.

### Public routes

Only `GET /health` and `GET /health/dependencies` need no token. `POST /auth/login` is
public. Everything else requires a valid bearer token. `GET /meta/severity-matrix`
requires authentication.

---

## 4. Conventions

### Error envelope

Every error uses:

```json
{
  "error": {
    "code": "conflict",
    "message": "This assessment already has a queued or running scan; wait for it or cancel it",
    "details": null
  }
}
```

`details` may contain `{"reasons": [...]}`, validation issue list, retry seconds or
other context. Never parse `message`; branch on `code` and HTTP status.

Validation errors return `422`:

```json
{
  "error": {
    "code": "validation_error",
    "message": "Request validation failed",
    "details": [
      {"loc": ["body", "title"], "msg": "String should have at least 1 character", "type": "string_too_short"}
    ]
  }
}
```

### Pagination

Paginated endpoints return:

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 20
}
```

Query params: `page` (>=1, default 1), `page_size` (1..100, default 20).
Paginated endpoints: assessments, users, scans list, findings list, reports list, audit
log. Scope list, evidence list and AI analyses are not paginated.

### Status codes

| Code | Meaning |
|---|---|
| `200` | Read/update/action success |
| `201` | Created |
| `202` | Async job accepted |
| `204` | Deleted, no body |
| `400` | Reserved; most input errors are 422 |
| `401` | Missing, invalid or expired token; invalid login |
| `403` | Role or scope violation |
| `404` | Entity not found |
| `409` | Conflict, invalid state, not ready |
| `413` | Evidence file too large |
| `422` | Validation or domain rule failure |
| `429` | Login throttle |
| `500` | Unexpected server failure |
| `502` | AI summary generation failed |

### Enums

```ts
type Role = "admin" | "assessor";

type AssessmentStatus =
  | "draft" | "ready" | "in_progress" | "in_review" | "completed" | "archived";

type ScopeKind = "host" | "ip" | "cidr" | "url_prefix" | "port";

type ScanTool = "nmap" | "zap" | "dig" | "whois" | "whatweb" | "curl" | "http_checks";

type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

type NmapProfile = "quick" | "standard" | "full_tcp";
type ZapProfile = "baseline" | "active_limited";
type HttpCheckProfile = "config_baseline" | "session" | "access_control" | "auth_limited";

type FindingSource = "nmap" | "zap" | "whatweb" | "http_checks" | "manual";

type FindingCategory =
  | "injection" | "authentication" | "session_management"
  | "security_configuration" | "information_disclosure"
  | "access_control" | "exposed_files" | "business_logic" | "uncategorized";

type Severity = "critical" | "high" | "medium" | "low" | "info";

type VerificationStatus = "pending" | "confirmed" | "false_positive" | "needs_retest";
type VerificationDecision = "confirmed" | "false_positive" | "needs_retest";

type EvidenceType = "tool_output" | "http_exchange" | "note" | "file";

type AIFunction = "interpret" | "remediate" | "summary";
type AIAnalysisStatus = "success" | "failed" | "invalid_output";
type SummaryStatus = "draft" | "approved" | "superseded";
type AIJobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

type ReportFormat = "pdf" | "html";
type ReportStatus = "pending" | "ready" | "failed";

type AuditOutcome = "allowed" | "denied";
type FindingSortField = "created_at" | "last_seen_at" | "severity" | "title";
type SortOrder = "asc" | "desc";
```

### Severity model

Likelihood and impact are integers 1..5. Server computes final severity. Client cannot
set `final_severity`.

| Score | Severity |
|---|---|
| 20–25 | critical |
| 12–19 | high |
| 6–11 | medium |
| 3–5 | low |
| 1–2 | info |

`GET /meta/severity-matrix` returns labels, scales and thresholds.

---

## 5. Core TypeScript types

```ts
type ISODate = string;

interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown | null;
  };
}

interface UserSummary {
  id: number;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
}

interface UserOut extends UserSummary {
  created_at: ISODate;
  updated_at: ISODate;
}

interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number; // seconds
  user: UserSummary;
}

interface AssessmentOut {
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

interface ScopeItemOut {
  id: number;
  assessment_id: number;
  kind: ScopeKind;
  value: string;
  in_scope: boolean;
  note: string | null;
  created_at: ISODate;
  updated_at: ISODate;
}

interface ScanOut {
  id: number;
  assessment_id: number;
  tool: ScanTool;
  profile: string;
  target: string;
  status: ScanStatus;
  progress: number; // 0..100
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

interface FindingOut {
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
  likelihood: number | null; // 1..5
  impact: number | null; // 1..5
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

interface FindingDetailOut extends FindingOut {
  raw: Record<string, unknown>;
}

interface EvidenceOut {
  id: number;
  finding_id: number | null;
  scan_id: number | null;
  type: EvidenceType;
  content: string | null;
  filename: string | null;
  has_file: boolean;
  download_url: string | null; // relative, e.g. /api/v1/evidence/12/download
  sha256: string | null;
  created_by: number | null;
  created_at: ISODate;
}

interface FindingAnalysisOut {
  finding_id: number;
  analyses: AIAnalysisOut[]; // interpret first, then remediate
}

interface AIAnalysisOut {
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

interface SummaryOut {
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

interface ReportOut {
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

interface AuditLogOut {
  id: number;
  assessment_id: number | null;
  user_id: number | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  details: Record<string, unknown>;
  created_at: ISODate;
}
```

### Dashboard types

```ts
interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface VerificationCounts {
  pending: number;
  confirmed: number;
  false_positive: number;
  needs_retest: number;
}

interface DashboardOut {
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
  ai_summary: SummaryOut | null; // approved summary only
  top_confirmed_findings: Array<{
    id: number;
    title: string;
    final_severity: string | null;
    category: string;
    affected_url: string | null;
  }>;
  last_updated_at: ISODate | null;
}
```

### HTTP-check types

```ts
interface LoginSpec {
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

interface AccessRule {
  path: string;
  method: "GET" | "HEAD" | "OPTIONS";
  allowed_roles: string[];
  id_template: boolean;
  sample_ids: string[]; // max 5
}

interface HttpCheckLimits {
  max_requests: number; // 1..500
  max_rps: number; // >0..10
  max_login_attempts: number; // 1..10
  min_login_interval_seconds: number; // 0..10
  max_redirects: number; // 0..3
}

interface HttpCheckConfigIn {
  login: LoginSpec | null;
  access_rules: AccessRule[];
  roles: string[]; // default ["staff","admin"]
  limits: HttpCheckLimits;
}

interface HttpCheckConfigOut extends HttpCheckConfigIn {
  id: number;
  assessment_id: number;
  updated_by: number | null;
  created_at: ISODate;
  updated_at: ISODate;
}

interface TestAccountCreate {
  role: string;
  username: string;
  password: string; // write-only
}

interface TestAccountOut {
  id: number;
  assessment_id: number;
  role: string;
  username: string;
  created_at: ISODate;
}
```

### AI / request types

```ts
interface BulkAnalyzeRequest {
  min_severity?: Severity | null;
  only_unanalyzed?: boolean; // default true
  force?: boolean; // default false
}

interface BulkAnalyzeQueued {
  job_id: number;
  assessment_id: number;
  status: AIJobStatus;
  total: number;
}

interface AIJobOut {
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

interface AIStatusOut {
  assessment_id: number;
  total_findings: number;
  findings_with_interpretation: number;
  findings_with_remediation: number;
  pending_findings: number;
  last_analyzed_at: ISODate | null;
  job: AIJobOut | null;
}

interface SummaryBundle {
  latest: SummaryOut | null;
  history: SummaryOut[];
}

interface SummaryEdit {
  text: string; // 1..6000
}

interface ReportCreate {
  format: ReportFormat;
}
```

---

## 6. API reference

All paths below are relative to `/api/v1`. “Auth” means any authenticated user unless
marked admin. Error responses are omitted from each row; every route uses the standard
error envelope.

### 6.1 Health

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/health` | public | `HealthResponse` |
| GET | `/health/dependencies` | public | `DependenciesResponse` |

`GET /health`:

```json
{"status":"ok","service":"penpal-backend","version":"0.1.0"}
```

`GET /health/dependencies`:

```json
{
  "status": "degraded",
  "dependencies": [
    {"name":"database","ok":true,"detail":"reachable"},
    {"name":"nmap","ok":false,"detail":"binary not found on PATH"},
    {"name":"zap","ok":false,"detail":"daemon unreachable"},
    {"name":"ai_provider","ok":true,"detail":"openai-compatible endpoint configured; fallback configured"}
  ]
}
```

`status` is `ok` only when all checks pass. Use for ops, not as a hard frontend gate.

### 6.2 Metadata

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/meta/severity-matrix` | bearer | `SeverityMatrixOut` |

Example:

```json
{
  "likelihood": {
    "minimum": 1,
    "maximum": 5,
    "labels": {"1":"rare","2":"unlikely","3":"possible","4":"likely","5":"almost certain"}
  },
  "impact": {
    "minimum": 1,
    "maximum": 5,
    "labels": {"1":"negligible","2":"minor","3":"moderate","4":"major","5":"severe"}
  },
  "thresholds": [
    {"min_score":1,"max_score":2,"severity":"info"},
    {"min_score":3,"max_score":5,"severity":"low"},
    {"min_score":6,"max_score":11,"severity":"medium"},
    {"min_score":12,"max_score":19,"severity":"high"},
    {"min_score":20,"max_score":25,"severity":"critical"}
  ],
  "formula": "score = likelihood x impact",
  "final_severity_source": "server"
}
```

### 6.3 Auth

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| POST | `/auth/login` | public | `LoginRequest` | `TokenResponse` |
| GET | `/auth/me` | bearer | — | `UserOut` |

```ts
interface LoginRequest {
  email: string; // valid email shape; .test/.local allowed
  password: string;
}
```

Login example:

```json
{"email":"admin@penpal.local","password":"<password>"}
```

Success `200`:

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "email": "admin@penpal.local",
    "full_name": "PenPal Administrator",
    "role": "admin",
    "is_active": true
  }
}
```

Failure: `401 invalid_credentials`, `429 too_many_attempts`.

### 6.4 Users (admin)

| Method | Path | Auth | Query/body | Response |
|---|---|---|---|---|
| POST | `/users` | admin | `UserCreate` | `201 UserOut` |
| GET | `/users` | admin | `q?`, `role?`, `is_active?`, pagination | `Page<UserOut>` |
| PATCH | `/users/{user_id}` | admin | `UserUpdate` | `UserOut` |

```ts
interface UserCreate {
  email: string;
  full_name: string; // 1..200
  password: string; // 12..200
  role?: Role; // default assessor
}

interface UserUpdate {
  full_name?: string;
  role?: Role;
  is_active?: boolean;
  password?: string; // 12..200
}
```

Admin cannot remove the last active admin or deactivate self. Errors: `409` for duplicate
email/self-lockout/last-admin, `404` unknown user.

### 6.5 Assessments

| Method | Path | Auth | Query/body | Response |
|---|---|---|---|---|
| POST | `/assessments` | bearer | `AssessmentCreate` | `201 AssessmentOut` |
| GET | `/assessments` | bearer | `q?`, `status?`, pagination | `Page<AssessmentOut>` |
| GET | `/assessments/{assessment_id}` | bearer | — | `AssessmentOut` |
| PATCH | `/assessments/{assessment_id}` | bearer | `AssessmentUpdate` | `AssessmentOut` |
| POST | `/assessments/{assessment_id}/confirm-authorization` | bearer | `ConfirmAuthorizationRequest` | `AssessmentOut` |
| POST | `/assessments/{assessment_id}/archive` | bearer | — | `AssessmentOut` |

```ts
interface AssessmentCreate {
  name: string; // 1..200
  description?: string | null;
  target_name: string; // 1..200
  target_base_url?: string | null; // absolute http(s), no userinfo
  target_description?: string | null;
  owner_name: string; // 1..200
  authorization_reference: string; // required
  hosting_environment?: string | null;
  selected_categories?: FindingCategory[];
}

interface AssessmentUpdate {
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

interface ConfirmAuthorizationRequest {
  note?: string | null; // max 2000
}

type AuthorizationFileStatus = "pending" | "verified" | "expired" | "revoked";

interface AuthorizationFileCreate {
  expires_in_hours?: number; // 1..720, default 24
  verification_path?: string; // default /.well-known/penpal-verification.txt
}

interface AuthorizationFileOut {
  id: number;
  assessment_id: number;
  created_by: number | null;
  target: string; // origin derived from assessment.target_base_url
  token: string;
  content: string; // token text to publish at verification_path
  verification_path: string;
  verification_url: string; // target + path
  status: AuthorizationFileStatus;
  expires_at: ISODate;
  revoked_at: ISODate | null;
  verified_at: ISODate | null;
  last_checked_at: ISODate | null;
  failure_reason: string | null;
  created_at: ISODate;
  updated_at: ISODate;
}
```

Create example:

```json
{
  "name": "LSRS assessment",
  "target_name": "Love & Styles Rental System",
  "target_base_url": "https://lsrsv2.ethiodeploy.app",
  "owner_name": "LSRS owners",
  "authorization_reference": "signed-authorization-letter.pdf",
  "hosting_environment": "Authorized deployed environment",
  "selected_categories": ["authentication", "access_control", "injection"]
}
```

New assessment starts `draft`; scans are refused until authorization is confirmed.
Archive blocks further scans and scope edits.

### 6.5.1 Authorization files

Target-ownership verification for an assessment target. Management is limited to the
assessment creator or an admin.

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| POST | `/assessments/{assessment_id}/authorization-files` | owner/admin | `AuthorizationFileCreate` | `201 AuthorizationFileOut` |
| GET | `/assessments/{assessment_id}/authorization-files` | owner/admin | — | `AuthorizationFileOut[]` |
| GET | `/authorization-files/{file_id}` | owner/admin | — | `AuthorizationFileOut` |
| GET | `/authorization-files/{file_id}/file` | owner/admin | — | text file attachment |
| POST | `/authorization-files/{file_id}/verify` | owner/admin | — | `AuthorizationFileOut` |
| POST | `/authorization-files/{file_id}/revoke` | owner/admin | — | `AuthorizationFileOut` |

- `target` is the origin of `assessment.target_base_url`; the assessment must have one.
- The token is unique and single-use per active record. Creating a new token revokes the
  previous active token for the same assessment/target.
- Publish `content` exactly at `verification_path` on the target. Verification fetches
  `verification_url`, does not follow redirects, reads at most 4 KiB, and requires
  HTTP 200 with a body equal to the token.
- Expired and revoked records return `409`; a remote missing file or mismatch returns
  `422`. Records are never deleted, so history and revocation remain inspectable.

```json
{
  "expires_in_hours": 24,
  "verification_path": "/.well-known/penpal-verification.txt"
}
```

### 6.6 Scope

| Method | Path | Auth | Query/body | Response |
|---|---|---|---|---|
| POST | `/assessments/{assessment_id}/scope-items` | bearer | `ScopeItemCreate` | `201 ScopeItemOut` |
| GET | `/assessments/{assessment_id}/scope-items` | bearer | `kind?`, `in_scope?` | `ScopeItemOut[]` |
| DELETE | `/assessments/{assessment_id}/scope-items/{item_id}` | bearer | — | `204` |
| POST | `/assessments/{assessment_id}/scope/check` | bearer | `ScopeCheckRequest` | `ScopeCheckResponse` |

```ts
interface ScopeItemCreate {
  kind: ScopeKind;
  value: string; // 1..2048
  in_scope?: boolean; // default true
  note?: string | null;
}

interface ScopeCheckRequest {
  target: string;
  tool: ScanTool;
  ports?: number[];
}

interface ScopeCheckResponse {
  allowed: boolean;
  reasons: string[];
  target: Record<string, unknown> | null;
  resolved_ips: string[];
  matched_rules: string[];
  zap_context_include: string[];
  zap_context_exclude: string[];
}
```

Examples:

```json
{"kind":"host","value":"lsrsv2.ethiodeploy.app","in_scope":true}
```
```json
{"kind":"url_prefix","value":"https://lsrsv2.ethiodeploy.app","in_scope":true}
```
```json
{"target":"https://lsrsv2.ethiodeploy.app/","tool":"http_checks"}
```

Dry-run check is audited and returns specific reasons. Out-of-scope beats in-scope.
Public hosts require `ALLOW_PUBLIC_TARGETS=true` plus exact `ALLOWED_PUBLIC_TARGETS`.

### 6.7 Scans

| Method | Path | Auth | Query/body | Response |
|---|---|---|---|---|
| POST | `/assessments/{assessment_id}/scans` | bearer | `ScanCreate` | `202 ScanQueuedOut` |
| GET | `/assessments/{assessment_id}/scans` | bearer | `status?`, `tool?`, pagination | `Page<ScanOut>` |
| GET | `/scans/{scan_id}` | bearer | — | `ScanOut` |
| POST | `/scans/{scan_id}/cancel` | bearer | — | `ScanOut` |
| GET | `/scans/{scan_id}/raw` | bearer | — | file attachment |

```ts
interface ScanCreate {
  tool: ScanTool;
  profile: string;
  target: string;
  ports?: number[];
  confirm_lockout_test?: boolean; // auth_limited only
}

interface ScanQueuedOut {
  scan_id: number;
  status: ScanStatus;
}
```

Profiles:

| Tool | Profiles | Target |
|---|---|---|
| `nmap` | `quick`, `standard`, `full_tcp` | host/IP; URL host + explicit port allowed |
| `zap` | `baseline`, `active_limited` | absolute http(s) URL |
| `dig` | `default` | host or IP |
| `whois` | `default` | host or IP; skipped for private targets |
| `whatweb` | `default` | absolute http(s) URL |
| `curl` | `default` | absolute http(s) URL |
| `http_checks` | `config_baseline`, `session`, `access_control`, `auth_limited` | absolute http(s) URL |

Create scan:

```json
{
  "tool": "zap",
  "profile": "baseline",
  "target": "https://lsrsv2.ethiodeploy.app/"
}
```

Response `202`:

```json
{"scan_id": 42, "status": "queued"}
```

Poll `GET /scans/42` until `status` is `completed`, `failed` or `cancelled`. Only one
queued/running scan per assessment; another request returns `409`. Raw output is
available only when `has_raw_output=true`; download with bearer auth. Media types:
Nmap XML, ZAP JSON, other tools text/plain or JSON.

### 6.8 Recon

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/assessments/{assessment_id}/recon` | bearer | `ReconOut` |

`ReconOut` aggregates completed scans:

```ts
interface ReconOut {
  assessment_id: number;
  generated_at: ISODate;
  totals: { scans: number; hosts: number; hosts_up: number; open_ports: number };
  scans: Array<{
    id: number; profile: string; target: string; status: string; progress: number;
    started_at: ISODate | null; finished_at: ISODate | null;
    duration_seconds: number | null; tool_version: string | null;
    raw_output_sha256: string | null; error: string | null; parse_error: string | null;
  }>;
  hosts: Array<{
    address: string; address_type: string; status: string;
    hostnames: string[]; os_matches: string[];
    ports: Array<{
      port: number; protocol: string; state: string; reason: string | null;
      service: {
        name: string | null; product: string | null; version: string | null;
        extrainfo: string | null; tunnel: string | null;
      } | null;
    }>;
    scan_ids: number[];
  }>;
  dns: Array<{ scan_id: number; target: string; records: Record<string,string[]>; record_count: number }>;
  whois: Array<{ scan_id: number; target: string; skipped: boolean; note: string | null; fields: Record<string,string> }>;
  technologies: Array<{ scan_id: number; target: string; status_code: number | null; targets: string[]; technologies: Record<string,string[]> }>;
  http: Array<{ scan_id: number; target: string; status_code: number | null; content_type: string | null; header_count: number; body_bytes: number; location: string | null }>;
}
```

### 6.9 Findings

| Method | Path | Auth | Query/body | Response |
|---|---|---|---|---|
| GET | `/assessments/{assessment_id}/findings` | bearer | filters + pagination | `Page<FindingOut>` |
| POST | `/assessments/{assessment_id}/findings` | bearer | `ManualFindingCreate` | `201 FindingDetailOut` |
| GET | `/findings/{finding_id}` | bearer | — | `FindingDetailOut` |
| PATCH | `/findings/{finding_id}/verify` | bearer | `FindingVerify` | `FindingDetailOut` |
| POST | `/findings/{finding_id}/evidence` | bearer | multipart | `201 EvidenceOut` |
| GET | `/findings/{finding_id}/evidence` | bearer | — | `EvidenceOut[]` |
| GET | `/evidence/{evidence_id}/download` | bearer | — | file attachment |

List filters:

| Param | Values |
|---|---|
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `status` | `pending`, `confirmed`, `false_positive`, `needs_retest` |
| `category` | FindingCategory |
| `source` | FindingSource |
| `q` | text search over title, description, URL, parameter |
| `sort` | `created_at`, `last_seen_at`, `severity`, `title` |
| `order` | `asc`, `desc` |

Severity filter/sort uses *effective* severity for listing: final severity for confirmed,
otherwise AI-suggested, otherwise tool severity. Dashboard uses separate confirmed and
unverified buckets.

Manual finding:

```ts
interface ManualFindingCreate {
  title: string; // 1..500
  description?: string | null;
  category?: FindingCategory; // default uncategorized
  severity: Severity; // tool severity
  affected_url?: string | null;
  http_method?: string | null; // max 20
  parameter?: string | null; // max 200
  cwe?: string | null;
  owasp_category?: string | null;
}
```

Verification:

```ts
interface FindingVerify {
  decision: VerificationDecision;
  final_severity?: Severity | null; // must be omitted; server returns 422 if sent
  likelihood?: number | null; // 1..5
  impact?: number | null; // 1..5
  final_remediation?: string | null;
  reason?: string | null;
}
```

Rules:

- `confirmed`: requires `likelihood` and `impact`. Server computes `final_severity`.
  If `final_remediation` omitted, latest successful AI remediation is accepted as-is;
  if none exists, `422`.
- `false_positive`: `reason` required, at least 10 chars. Clears L/I, final severity and
  final remediation.
- `needs_retest`: L/I optional; final severity computed only when both supplied.
- `final_severity` is read-only. Sending it returns `422`.

Verify example:

```json
{
  "decision": "confirmed",
  "likelihood": 4,
  "impact": 4,
  "final_remediation": "Use parameterised queries and validate input."
}
```

Evidence upload is `multipart/form-data`, exactly one of:

- `note`: text note
- `file`: PNG, JPEG, TXT or PDF; max `MAX_UPLOAD_BYTES` (default 5 MB); extension,
  MIME and magic bytes checked; stored under a random filename.

```bash
curl -X POST "$BASE/findings/12/evidence" \
  -H "Authorization: Bearer $TOKEN" \
  -F "note=Manual reproduction notes"
```

`EvidenceOut.download_url` is relative; send bearer auth and read as blob.

### 6.10 HTTP checks

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| GET | `/assessments/{assessment_id}/http-check-config` | bearer | — | `HttpCheckConfigOut` |
| PUT | `/assessments/{assessment_id}/http-check-config` | bearer | `HttpCheckConfigIn` | `HttpCheckConfigOut` |
| GET | `/assessments/{assessment_id}/test-accounts` | bearer | — | `TestAccountOut[]` |
| POST | `/assessments/{assessment_id}/test-accounts` | bearer | `TestAccountCreate` | `201 TestAccountOut` |
| DELETE | `/assessments/{assessment_id}/test-accounts/{account_id}` | bearer | — | `204` |

Config example:

```json
{
  "login": {
    "url": "/login",
    "content_type": "form",
    "username_field": "username",
    "password_field": "password",
    "success_status": 200
  },
  "access_rules": [
    {"path": "/admin", "method": "GET", "allowed_roles": ["admin"]}
  ],
  "roles": ["staff", "admin"],
  "limits": {
    "max_requests": 200,
    "max_rps": 2,
    "max_login_attempts": 5,
    "min_login_interval_seconds": 1,
    "max_redirects": 3
  }
}
```

Test account:

```json
{"role":"staff","username":"staff01","password":"<write-only-password>"}
```

Passwords are never returned or logged. `GET` config returns `404` until first `PUT`.
HTTP checks run only through the scan endpoint with `tool=http_checks`.

### 6.11 AI

| Method | Path | Auth | Query/body | Response |
|---|---|---|---|---|
| POST | `/findings/{finding_id}/analyze` | bearer | `force?` | `200 FindingAnalysisOut {finding_id, analyses[]}` |
| POST | `/assessments/{assessment_id}/analyze` | bearer | `BulkAnalyzeRequest` | `202 BulkAnalyzeQueued` |
| GET | `/assessments/{assessment_id}/ai-status` | bearer | — | `AIStatusOut` |
| GET | `/findings/{finding_id}/ai-analyses` | bearer | — | `AIAnalysisOut[]` |
| POST | `/assessments/{assessment_id}/summary/generate` | bearer | `force?` | `SummaryOut` |
| GET | `/assessments/{assessment_id}/summary` | bearer | — | `SummaryBundle` |
| PATCH | `/summaries/{summary_id}` | bearer | `SummaryEdit` | `SummaryOut` |
| POST | `/summaries/{summary_id}/approve` | bearer | — | `SummaryOut` |

`POST /findings/{id}/analyze` returns `200` with `FindingAnalysisOut`, not a bare array:

```json
{
  "finding_id": 12,
  "analyses": [
    {
      "id": 91,
      "finding_id": 12,
      "assessment_id": 3,
      "function": "interpret",
      "provider": "openai_compat",
      "model": "nvidia/nemotron-3-ultra-550b-a55b",
      "prompt_version": "2026-11-24.1",
      "input_hash": "<sha256>",
      "sanitized_input": "FUNCTION: interpret ...",
      "output": { "suggested_severity": "high" },
      "status": "success",
      "error": null,
      "latency_ms": 1823,
      "prompt_tokens": 0,
      "completion_tokens": 0,
      "redaction_report": { "cookie_header": 1 },
      "attempts": [
        {
          "provider": "openai_compat",
          "model": "nvidia/nemotron-3-ultra-550b-a55b",
          "outcome": "success",
          "latency_ms": 1823,
          "error_class": null
        }
      ],
      "created_at": "2026-11-25T12:34:56Z"
    },
    {
      "id": 92,
      "finding_id": 12,
      "assessment_id": 3,
      "function": "remediate",
      "provider": "openai_compat",
      "model": "nvidia/nemotron-3-ultra-550b-a55b",
      "prompt_version": "2026-11-24.1",
      "input_hash": "<sha256>",
      "sanitized_input": "FUNCTION: remediate ...",
      "output": { "summary": "Use parameterised queries." },
      "status": "success",
      "error": null,
      "latency_ms": 1650,
      "prompt_tokens": 0,
      "completion_tokens": 0,
      "redaction_report": { "cookie_header": 1 },
      "attempts": [],
      "created_at": "2026-11-25T12:34:58Z"
    }
  ]
}
```

Both functions are always attempted. If one fails, its row has `status: "failed"` or
`"invalid_output"`, `output: null` and an `error`; the HTTP request still returns `200`.

Bulk request:

```json
{"min_severity":"medium","only_unanalyzed":true,"force":false}
```

Bulk response `202`:

```json
{"job_id":7,"assessment_id":3,"status":"queued","total":18}
```

Poll `GET /assessments/3/ai-status` until `job.status` is terminal. Progress is in memory;
a restart loses progress, results remain in `ai_analyses`.

Summary workflow:

1. `POST /summary/generate` creates a `draft`.
2. `PATCH /summaries/{id}` edits the text. Editing an approved summary resets it to draft.
3. `POST /summaries/{id}/approve` approves it and supersedes the previous approved summary.
4. Report uses the approved summary for AI prose. If none is approved, the report uses a
   deterministic server summary. Unapproved drafts go to the AI appendix.

Summary edit:

```json
{"text":"Assessor-edited summary text."}
```

### 6.12 Dashboard

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/assessments/{assessment_id}/dashboard` | bearer | `DashboardOut` |

- `severity_confirmed`: confirmed findings by server-computed final severity.
- `severity_unverified`: pending/needs-retest findings, split by AI or tool basis.
- False positives are excluded from severity and category counts.
- `status_counts` includes all statuses.
- `top_confirmed_findings`: up to 5.
- `ai_summary`: approved summary only, else `null`.

### 6.13 Audit

| Method | Path | Auth | Query | Response |
|---|---|---|---|---|
| GET | `/assessments/{assessment_id}/audit-log` | bearer | `action?`, `entity_type?`, `user_id?`, `outcome?`, `from?`, `to?`, pagination | `Page<AuditLogOut>` |
| GET | `/assessments/{assessment_id}/audit-log/export` | bearer | same filters + `format=csv\|json` | file/JSON |

`outcome` is `allowed` or `denied` for scope/http-check request events. `from`/`to` are
ISO datetimes. CSV prefixes cells starting with `=`, `+`, `-`, `@` to block spreadsheet
formula injection. JSON export returns an array of `AuditLogOut`.

### 6.14 Reports

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| POST | `/assessments/{assessment_id}/reports` | bearer | `ReportCreate` | `201 ReportOut` |
| GET | `/assessments/{assessment_id}/reports` | bearer | pagination | `Page<ReportOut>` |
| GET | `/reports/{report_id}/download` | bearer | — | file attachment |

```json
{"format":"html"}
```

`format` is `html` or `pdf`. Only confirmed findings are in the main body. If PDF
rendering fails, the report row is `ready` with `format=html`, `error` explains the
fallback, and `summary_counts.pdf_fallback=true`.

---

## 7. Async jobs and polling

No WebSockets. Use polling.

### Scan

```text
POST /assessments/{id}/scans -> 202 {scan_id, status:"queued"}
GET /scans/{scan_id} every 1-2s
```

Terminal: `completed`, `failed`, `cancelled`. `progress` is 0..100. `error` is safe text.
Cancel: `POST /scans/{scan_id}/cancel`; 409 if already terminal.

### Bulk AI

```text
POST /assessments/{id}/analyze -> 202 {job_id,total}
GET /assessments/{id}/ai-status -> job {status,processed,failed}
```

Only one active bulk job per assessment. AI failure does not block scans, finding views,
verification, dashboard or reports.

### Reports

Report creation is synchronous and returns `201` with `status=ready` or `failed`.
Poll/list reports only if you need history. Download only when `has_file=true`.

---

## 8. Error and edge-case matrix

| Situation | Status | Code |
|---|---|---|
| Missing/invalid/expired token | 401 | `not_authenticated` / `invalid_token` |
| Bad email/password | 401 | `invalid_credentials` |
| Login throttle | 429 | `too_many_attempts` |
| Admin-only route as assessor | 403 | `forbidden` |
| Unknown entity | 404 | `not_found` |
| Duplicate email/manual finding/test account | 409 | `conflict` |
| Duplicate active scan/bulk AI/summary conflict | 409 | `conflict` |
| Target outside scope / unauthorized assessment | 403 | `scope_violation` |
| Malformed scan request | 422 | `invalid_scan_request` |
| Verify rule violation | 422 | `invalid_verification` |
| Evidence rule violation | 422 | `invalid_evidence` |
| Evidence upload too large | 413 | `file_too_large` |
| Evidence is not a file | 409 | `evidence_not_a_file` |
| Report not ready | 409 | `report_not_ready` |
| Raw output unavailable | 409 | `raw_output_unavailable` |
| No confirmed findings for summary | 409 | `no_confirmed_findings` |
| Authorization file expired/revoked | 409 | `authorization_file_expired` / `authorization_file_revoked` |
| Authorization token missing/mismatched | 422 | `authorization_file_unavailable` / `authorization_file_mismatch` |
| Authorization verification unreachable | 422 | `authorization_file_unreachable` |
| Assessment target missing for authorization file | 422 | `authorization_target_required` |
| AI summary generation failed | 502 | `summary_generation_failed` |
| Report generation failed | 500 | `report_generation_failed` |
| Validation failure | 422 | `validation_error` |

Event names in audit log include `auth.login_success`, `auth.login_failed`,
`assessment.created`, `assessment.authorization_confirmed`, `scope.checked`,
`scope.item_added`, `scan.requested`, `scan.started`, `scan.completed`, `scan.failed`,
`scan.cancelled`, `finding.created`, `finding.verified`, `evidence.added`,
`ai.analyzed`, `ai.bulk_requested`, `summary.generated`, `summary.edited`,
`summary.approved`, `http_check.request`, `http_checks.config_updated`,
`test_account.created`, `test_account.deleted`,
`authorization_file.created`, `authorization_file.verified`,
`authorization_file.verification_failed`, `authorization_file.revoked`,
`report.generated`.

---

## 9. Frontend integration notes

### Recommended flow

1. Login; keep token.
2. Create assessment; add scope; confirm authorization.
3. Request scans one at a time; poll scan detail.
4. Load findings; use filters and pagination.
5. Run single or bulk AI; display AI-suggested values separately from final values.
6. Verify findings with L/I; display final severity read-only.
7. Generate/edit/approve summary.
8. Show dashboard.
9. Generate report; download blob.
10. Show audit log filtered by action/outcome.

### File handling

- Raw scan: `GET /scans/{id}/raw` returns XML/JSON/text attachment.
- Evidence upload: multipart, one file or note.
- Evidence download: use `download_url`, bearer auth, blob URL.
- Report download: bearer auth, blob URL. Check `format` if you requested PDF.
- `Content-Disposition` is exposed by CORS; use it for filename.

### Time and severity display

- Always show AI-suggested severity labelled as advisory.
- Final severity only exists after confirmation.
- Show L/I and score rationale in verification UI.
- Dashboard headline uses confirmed only; unverified series separately.

### Public target reminder

The deployed LSRS host is allowed only when backend env has exact
`ALLOWED_PUBLIC_TARGETS` and `ALLOW_PUBLIC_TARGETS=true`, and the host is in assessment
scope. Frontend must still call `/scope/check` or rely on scan errors.

---

## 10. Generated artifacts

- `docs/openapi.json` - complete OpenAPI 3 schema, 45 paths / 56 operations.
- Regenerate:

```bash
cd Backend
python scripts/export_openapi.py
```

- Migration head: `f4a5b6c7d8e9`.
- Verification run: 271 pytest tests, ruff clean.
- Docker smoke test passed on 2026-11-25: Nmap, dig, whois skip, WhatWeb, ZAP baseline,
  HTTP config checks, bulk AI, L/I verification, summary approval, dashboard, PDF
  report/download and audit trail. The Windows host itself lacks the tool binaries and
  PDF system libs; use the Compose stack and `scripts/smoke_e2e.py` for real-tool checks.

---

## 11. Known backend gaps relevant to frontend

- No refresh token; re-login on expiry.
- No WebSocket/webhook; poll.
- Lockout test for `auth_limited` only when `confirm_lockout_test=true`; idle timeout and
  post-logout replay are manual.
- IDOR sample-ID templating is not implemented.
- `http_checks` report progress only at start/end; no per-request progress.
- Bulk AI job state is in memory; restart loses job progress.
- PDF fallback may return HTML; check `format`.
- No evidence-file preview endpoint; download only.
