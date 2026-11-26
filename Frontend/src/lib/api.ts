import type {
  AIAnalysisOut,
  AIStatusOut,
  AssessmentCreate,
  AssessmentOut,
  AssessmentUpdate,
  AuditFilters,
  AuditLogOut,
  BulkAnalyzeQueued,
  BulkAnalyzeRequest,
  DashboardOut,
  DependenciesResponse,
  EvidenceOut,
  FindingAnalysisOut,
  FindingDetailOut,
  FindingFilters,
  FindingOut,
  FindingVerify,
  HealthResponse,
  HttpCheckConfigIn,
  HttpCheckConfigOut,
  LoginRequest,
  ManualFindingCreate,
  Page,
  ReconOut,
  ReportFormat,
  ReportOut,
  ScanCreate,
  ScanOut,
  ScanQueuedOut,
  ScopeCheckRequest,
  ScopeCheckResponse,
  ScopeItemCreate,
  ScopeItemOut,
  SeverityMatrixOut,
  SummaryBundle,
  SummaryOut,
  TestAccountCreate,
  TestAccountOut,
  TokenResponse,
  UserCreate,
  UserOut,
  UserUpdate,
  ValidationIssue,
} from "./types";

export const API_BASE =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";

type QueryValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | ReadonlyArray<string | number>;

export function buildQuery(params?: object): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params) as [string, QueryValue][]) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, String(item));
    } else {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  readonly retryAfter: number | null;

  constructor(
    status: number,
    code: string,
    message: string,
    details: unknown = null,
    retryAfter: number | null = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfter = retryAfter;
  }
}

let accessToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function onUnauthorized(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

function apiUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) return path;
  const base = API_BASE.replace(/\/+$/, "");
  let basePath = "";
  if (base.startsWith("/")) {
    basePath = base;
  } else {
    try {
      basePath = new URL(base).pathname.replace(/\/+$/, "");
    } catch {
      basePath = "";
    }
  }
  // Download URLs from the backend are absolute paths like /api/v1/evidence/1/download.
  if (
    basePath &&
    (path === basePath || path.startsWith(`${basePath}/`))
  ) {
    return `${base}${path.slice(basePath.length)}`;
  }
  return `${base}${path.startsWith("/") ? path : `/${path}`}`;
}

function parseFilename(header: string | null): string | null {
  if (!header) return null;
  const utf8 = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (utf8?.[1]) {
    try {
      return decodeURIComponent(utf8[1].replace(/^"|"$/g, ""));
    } catch {
      return utf8[1];
    }
  }
  const plain = /filename="?([^";]+)"?/i.exec(header);
  return plain?.[1] ?? null;
}

function parseRetryAfter(header: string | null): number | null {
  if (!header) return null;
  const seconds = Number(header);
  return Number.isFinite(seconds) ? seconds : null;
}

interface SendOptions {
  query?: object;
  body?: unknown;
  formData?: FormData;
  auth?: boolean;
}

async function send<T>(
  method: string,
  path: string,
  options: SendOptions = {},
): Promise<T> {
  const {
    query,
    body,
    formData,
    auth = true,
  } = options;

  const headers: Record<string, string> = { Accept: "application/json" };
  if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let payload: BodyInit | undefined;
  if (formData) {
    payload = formData;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  const response = await fetch(apiUrl(path) + buildQuery(query), {
    method,
    headers,
    body: payload,
  });

  if (!response.ok) {
    let parsed: unknown = null;
    const text = await response.text();
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
    }
    const envelope =
      parsed && typeof parsed === "object" && "error" in parsed
        ? (parsed as { error?: { code?: string; message?: string; details?: unknown } })
        : null;
    const error = new ApiError(
      response.status,
      envelope?.error?.code ?? `http_${response.status}`,
      envelope?.error?.message ?? `Request failed (HTTP ${response.status})`,
      envelope?.error?.details ?? null,
      parseRetryAfter(response.headers.get("Retry-After")),
    );
    if (response.status === 401 && auth && path !== "/auth/login") {
      unauthorizedHandler?.();
    }
    throw error;
  }

  if (response.status === 204) return undefined as T;
  const text = await response.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

async function download(
  path: string,
  query?: object,
): Promise<{ blob: Blob; filename: string | null }> {
  const headers: Record<string, string> = {};
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(apiUrl(path) + buildQuery(query), { headers });
  if (!response.ok) {
    const text = await response.text();
    let code = `http_${response.status}`;
    let message = `Download failed (HTTP ${response.status})`;
    let details: unknown = null;
    try {
      const parsed = JSON.parse(text) as {
        error?: { code?: string; message?: string; details?: unknown };
      };
      code = parsed.error?.code ?? code;
      message = parsed.error?.message ?? message;
      details = parsed.error?.details ?? null;
    } catch {
      // Keep the generic message for non-JSON errors.
    }
    if (response.status === 401) unauthorizedHandler?.();
    throw new ApiError(response.status, code, message, details);
  }
  return {
    blob: await response.blob(),
    filename: parseFilename(response.headers.get("Content-Disposition")),
  };
}

export async function saveBlob(
  blob: Blob,
  filename: string | null,
  fallback: string,
): Promise<void> {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename ?? fallback;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export interface ListParams {
  page?: number;
  page_size?: number;
}

export const api = {
  health: {
    status: () =>
      send<HealthResponse>("GET", "/health", { auth: false }),
    dependencies: () =>
      send<DependenciesResponse>("GET", "/health/dependencies", {
        auth: false,
      }),
  },

  auth: {
    login: (body: LoginRequest) =>
      send<TokenResponse>("POST", "/auth/login", { body, auth: false }),
    me: () => send<UserOut>("GET", "/auth/me"),
  },

  meta: {
    severityMatrix: () => send<SeverityMatrixOut>("GET", "/meta/severity-matrix"),
  },

  users: {
    list: (params: ListParams & { q?: string; role?: string; is_active?: boolean }) =>
      send<Page<UserOut>>("GET", "/users", { query: params }),
    create: (body: UserCreate) => send<UserOut>("POST", "/users", { body }),
    update: (id: number, body: UserUpdate) =>
      send<UserOut>("PATCH", `/users/${id}`, { body }),
  },

  assessments: {
    list: (params: ListParams & { q?: string; status?: string }) =>
      send<Page<AssessmentOut>>("GET", "/assessments", { query: params }),
    get: (id: number) => send<AssessmentOut>("GET", `/assessments/${id}`),
    create: (body: AssessmentCreate) =>
      send<AssessmentOut>("POST", "/assessments", { body }),
    update: (id: number, body: AssessmentUpdate) =>
      send<AssessmentOut>("PATCH", `/assessments/${id}`, { body }),
    confirmAuthorization: (id: number, note?: string | null) =>
      send<AssessmentOut>("POST", `/assessments/${id}/confirm-authorization`, {
        body: { note: note ?? null },
      }),
    archive: (id: number) =>
      send<AssessmentOut>("POST", `/assessments/${id}/archive`),
  },

  scope: {
    list: (
      assessmentId: number,
      params?: { kind?: string; in_scope?: boolean },
    ) =>
      send<ScopeItemOut[]>("GET", `/assessments/${assessmentId}/scope-items`, {
        query: params,
      }),
    create: (assessmentId: number, body: ScopeItemCreate) =>
      send<ScopeItemOut>("POST", `/assessments/${assessmentId}/scope-items`, {
        body,
      }),
    remove: (assessmentId: number, itemId: number) =>
      send<void>("DELETE", `/assessments/${assessmentId}/scope-items/${itemId}`),
    check: (assessmentId: number, body: ScopeCheckRequest) =>
      send<ScopeCheckResponse>(
        "POST",
        `/assessments/${assessmentId}/scope/check`,
        { body },
      ),
  },

  scans: {
    list: (
      assessmentId: number,
      params: ListParams & { status?: string; tool?: string },
    ) =>
      send<Page<ScanOut>>("GET", `/assessments/${assessmentId}/scans`, {
        query: params,
      }),
    create: (assessmentId: number, body: ScanCreate) =>
      send<ScanQueuedOut>("POST", `/assessments/${assessmentId}/scans`, { body }),
    get: (scanId: number) => send<ScanOut>("GET", `/scans/${scanId}`),
    cancel: (scanId: number) =>
      send<ScanOut>("POST", `/scans/${scanId}/cancel`),
    raw: (scanId: number) => download(`/scans/${scanId}/raw`),
  },

  recon: {
    get: (assessmentId: number) =>
      send<ReconOut>("GET", `/assessments/${assessmentId}/recon`),
  },

  findings: {
    list: (assessmentId: number, filters: FindingFilters) =>
      send<Page<FindingOut>>("GET", `/assessments/${assessmentId}/findings`, {
        query: filters,
      }),
    get: (findingId: number) =>
      send<FindingDetailOut>("GET", `/findings/${findingId}`),
    create: (assessmentId: number, body: ManualFindingCreate) =>
      send<FindingDetailOut>(
        "POST",
        `/assessments/${assessmentId}/findings`,
        { body },
      ),
    verify: (findingId: number, body: FindingVerify) =>
      send<FindingDetailOut>("PATCH", `/findings/${findingId}/verify`, { body }),
    evidence: {
      list: (findingId: number) =>
        send<EvidenceOut[]>("GET", `/findings/${findingId}/evidence`),
      upload: (findingId: number, input: { note?: string; file?: File }) => {
        const formData = new FormData();
        if (input.file) formData.append("file", input.file);
        if (input.note !== undefined) formData.append("note", input.note);
        return send<EvidenceOut>(
          "POST",
          `/findings/${findingId}/evidence`,
          { formData },
        );
      },
      download: (downloadUrl: string) => download(downloadUrl),
    },
  },

  httpChecks: {
    getConfig: (assessmentId: number) =>
      send<HttpCheckConfigOut>(
        "GET",
        `/assessments/${assessmentId}/http-check-config`,
      ),
    putConfig: (assessmentId: number, body: HttpCheckConfigIn) =>
      send<HttpCheckConfigOut>(
        "PUT",
        `/assessments/${assessmentId}/http-check-config`,
        { body },
      ),
    listAccounts: (assessmentId: number) =>
      send<TestAccountOut[]>(
        "GET",
        `/assessments/${assessmentId}/test-accounts`,
      ),
    createAccount: (assessmentId: number, body: TestAccountCreate) =>
      send<TestAccountOut>(
        "POST",
        `/assessments/${assessmentId}/test-accounts`,
        { body },
      ),
    deleteAccount: (assessmentId: number, accountId: number) =>
      send<void>(
        "DELETE",
        `/assessments/${assessmentId}/test-accounts/${accountId}`,
      ),
  },

  ai: {
    analyze: (findingId: number, force = false) =>
      send<FindingAnalysisOut>(
        "POST",
        `/findings/${findingId}/analyze`,
        { query: { force } },
      ),
    analyses: (findingId: number) =>
      send<AIAnalysisOut[]>("GET", `/findings/${findingId}/ai-analyses`),
    bulk: (assessmentId: number, body: BulkAnalyzeRequest) =>
      send<BulkAnalyzeQueued>(
        "POST",
        `/assessments/${assessmentId}/analyze`,
        { body },
      ),
    status: (assessmentId: number) =>
      send<AIStatusOut>("GET", `/assessments/${assessmentId}/ai-status`),
  },

  summary: {
    generate: (assessmentId: number, force = false) =>
      send<SummaryOut>(
        "POST",
        `/assessments/${assessmentId}/summary/generate`,
        { query: { force } },
      ),
    get: (assessmentId: number) =>
      send<SummaryBundle>("GET", `/assessments/${assessmentId}/summary`),
    edit: (summaryId: number, text: string) =>
      send<SummaryOut>("PATCH", `/summaries/${summaryId}`, { body: { text } }),
    approve: (summaryId: number) =>
      send<SummaryOut>("POST", `/summaries/${summaryId}/approve`),
  },

  dashboard: {
    get: (assessmentId: number) =>
      send<DashboardOut>("GET", `/assessments/${assessmentId}/dashboard`),
  },

  audit: {
    list: (assessmentId: number, filters: AuditFilters) =>
      send<Page<AuditLogOut>>(
        "GET",
        `/assessments/${assessmentId}/audit-log`,
        { query: filters },
      ),
    export: (assessmentId: number, filters: AuditFilters, format: "csv" | "json") =>
      download(`/assessments/${assessmentId}/audit-log/export`, {
        ...filters,
        format,
      }),
  },

  reports: {
    list: (assessmentId: number, params: ListParams) =>
      send<Page<ReportOut>>("GET", `/assessments/${assessmentId}/reports`, {
        query: params,
      }),
    create: (assessmentId: number, format: ReportFormat) =>
      send<ReportOut>("POST", `/assessments/${assessmentId}/reports`, {
        body: { format },
      }),
    download: (reportId: number) => download(`/reports/${reportId}/download`),
  },
};

/** Human-readable error that branches on code, never on the message text. */
export function formatApiError(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return error instanceof Error ? error.message : "Unexpected error";
  }
  const detail = validationDetail(error.details);
  const retry =
    error.status === 429 && error.retryAfter
      ? ` Try again in ${error.retryAfter}s.`
      : "";
  const scopeReasons = error.details
    ? reasonsFromDetails(error.details)
    : [];
  const base = detail ? `${error.message}: ${detail}` : error.message;
  return `${base}${scopeReasons.length ? ` (${scopeReasons.join("; ")})` : ""}${retry}`;
}

function validationDetail(details: unknown): string | null {
  if (!Array.isArray(details)) return null;
  const issues = details.filter(
    (item): item is ValidationIssue =>
      typeof item === "object" &&
      item !== null &&
      "msg" in item &&
      typeof (item as ValidationIssue).msg === "string",
  );
  if (issues.length === 0) return null;
  const issue = issues[0];
  if (!issue) return null;
  const where = issue.loc
    .filter((part) => part !== "body" && part !== "query")
    .join(".");
  return where ? `${where}: ${issue.msg}` : issue.msg;
}

function reasonsFromDetails(details: unknown): string[] {
  if (typeof details !== "object" || details === null) return [];
  const reasons = (details as { reasons?: unknown }).reasons;
  if (!Array.isArray(reasons)) return [];
  return reasons.filter((item): item is string => typeof item === "string");
}
