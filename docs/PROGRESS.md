# PenPal backend progress

Newest entry first. Each phase ends with tests, a running app check, and a commit.

## 2026-11-24 — Phase 7: HTML and PDF reports

- `report.html.j2` covers cover, scope/authorization, methodology, executive summary, confirmed findings with evidence and remediation, Appendix A verification outcomes, Appendix B AI usage/redaction disclosure and Appendix C scan log.
- Only assessor-confirmed findings enter the main report. Tool, AI and pending findings stay out; rejected and needs-retest counts go to Appendix A.
- Autoescaping is explicit (`autoescape=True`) because the `.j2` suffix would otherwise disable Jinja's extension-based autoescape. Titles, descriptions and evidence render escaped; a regression test uses script/img payloads.
- Evidence excerpts are truncated to `REPORT_EVIDENCE_MAX_CHARS` per item; each item keeps its type, stored filename and SHA-256. Full evidence stays in the database.
- The executive summary is deterministic text from counts, not AI prose. Appendix B lists provider/model usage and aggregates the stored redaction reports.
- Files are written under `DATA_DIR/reports/{assessment_id}/report-{id}.{html|pdf}` and hashed with SHA-256. Downloads resolve inside `DATA_DIR`.
- `POST /assessments/{id}/reports`, `GET /assessments/{id}/reports`, `GET /reports/{id}/download`.
- PDF rendering is injectable for tests. If WeasyPrint fails, the HTML file is kept and a ready HTML report row is returned with the reason and `pdf_fallback=true`, so the HTML report still works.
- Tests: confirmed-only content, escaping, truncation, scope/AI/scan sections, SHA-256, download, PDF success, PDF fallback, not-ready and unsafe-path refusals. Full suite: 203 passed.
- App start check: OpenAPI generation (30 paths) and lifespan health check pass locally.
- Not verified here: real WeasyPrint PDF output on this Windows host (system Pango/GTK libraries); the container installs the required libraries. PDF generation is covered with an injected renderer.

Next: hardening, demo seed data, README and final verification.

## 2026-11-24 — Phase 6: verification, evidence, audit and dashboard

- Findings API: paginated list with effective-severity/status/category/source filters, `q` search, severity/title/date sorting, detail with the tool payload, and manual finding creation.
- Manual findings start `pending`, carry `source=manual`, use a stable title/endpoint/parameter fingerprint, and are duplicate-guarded per assessment.
- Verification rules: false positives need a reason of at least 10 characters; confirmed findings need a final severity or fall back to AI-suggested then tool severity, with `severity_defaulted` in the audit row. Decisions can change and every previous/new state is audited.
- Evidence: text notes or one file per request. Files are capped by `MAX_UPLOAD_BYTES`, restricted to png/jpg/jpeg/txt/pdf, checked for matching extension, MIME type and magic bytes, stored under a random name, and hashed.
- Audit endpoint: newest-first paginated read of the append-only trail.
- Dashboard: one aggregate endpoint with effective severity counts (basis labelled), verification and category counts, scan history/duration, AI coverage, top confirmed findings and last-updated time. No per-finding queries.
- AI cannot write final severity, verification state or final remediation; a regression test re-analyzes a confirmed finding and checks those fields survive.
- Tests: filter/sort/pagination, manual finding guards, verification rule and default-severity paths, audit history, note and file evidence validation (extension, MIME, signature, size), dashboard counts, empty dashboard and audit pagination. Full suite: 198 passed.
- App start check: OpenAPI generation (28 paths) and lifespan health check pass locally.

Next: report builder, HTML/PDF and download endpoint.

## 2026-11-24 — Phase 5: sanitizer and advisory AI layer

- `sanitizer.py`: idempotent redaction of cookie/authorization/API-key headers, JWTs and bearer/basic tokens, provider key patterns, private keys, long hex/base64 secrets, sensitive parameter values, query values (names kept), URL userinfo and hosts, emails, phones, Luhn-valid card numbers and all IPv4/IPv6 addresses. Returns per-type counts and truncates to `AI_MAX_EVIDENCE_CHARS`.
- AI input uses the relative endpoint path, drops full HTTP messages (they are separate evidence), sanitizes up to five evidence rows and the normalizer payload, and stores the exact sent prompt plus the redaction report in `ai_analyses`.
- Provider interface `complete_json(system, user, *, max_tokens)` with `MockProvider` (deterministic, no network) and one `OpenAICompatProvider` for Gemini/Groq/OpenRouter/Ollama. JSON mode with a one-time fallback when a gateway rejects `response_format`.
- Two functions with shared versioned prompts and strict Pydantic schemas (`extra="forbid"`): `interpret` and `remediate`. Target data sits inside `<finding_data>` and is declared untrusted.
- Robustness: transient provider errors retry with backoff and jitter (3 attempts), invalid output gets exactly one repair retry, every attempt is persisted, process-wide RPM/concurrency limiting, and caching by provider/model/prompt version/sanitized prompt.
- Endpoints: `POST /findings/{id}/analyze`, `POST /assessments/{id}/analyze` (background bulk with `min_severity`, `only_unanalyzed`), `GET /assessments/{id}/ai-status`, `GET /findings/{id}/ai-analyses`.
- AI sets only `ai_suggested_severity`; it never writes `final_severity`, `verification_status`, or final remediation. Audit rows record every attempt.
- Tests: sanitizer table and idempotence tests (93% statement/branch coverage on the module), provider request/error/fallback tests, service cache/repair/retry/concurrency tests, and API single/bulk/status/failure tests. Full suite: 187 passed.
- App start check: OpenAPI generation (22 paths) and lifespan health check pass locally.
- Not verified here: a real hosted AI call. Tests never reach a provider; `AI_PROVIDER=mock` drives the demo path.

Next: verification, manual findings and evidence upload, audit log, dashboard.

## 2026-11-24 — Phase 4: ZAP integration and finding normalizer

- `ZapClient` wraps only the REST calls PenPal needs (`core`, `context`, `spider`, `pscan`, `ascan`, `alert`); the API key travels in `X-ZAP-API-Key`, never in a URL.
- `ZapScanRunner`: new session/context, scope-derived include/exclude regexes, spider, passive-scan drain, optional bounded active scan, alert pagination and sampled HTTP messages. Context is removed and the client closed even after failure or cancellation.
- Raw ZAP evidence is a PenPal wrapper document (`tool`, `version`, `profile`, `target`, `context`, `counts`, `alerts`) stored as `zap.json` with SHA-256; message bodies are truncated to the configured limit.
- Finding normalizer maps ZAP alerts by plugin id, CWE and tags to PenPal categories/OWASP, and Nmap notable services/versions to findings. Fingerprints strip URL queries so re-scans update rows instead of duplicating them.
- Re-scans preserve verification state, final severity, final remediation and AI suggestions; they update tool fields and bump `seen_count`. HTTP exchanges become `http_exchange` evidence, deduped by SHA-256 per finding.
- Scan manager parses and normalizes both tools after completion; a ZAP parse failure stores raw output and fails the scan with a safe message, while a ZAP client error fails the scan without a traceback leak.
- Tests: ZAP client headers/endpoints/retries/errors, runner baseline/active/order/cancel/timeout/pagination/truncation, fingerprint and mapping tables, Nmap and ZAP upsert, evidence dedupe, API end-to-end ZAP scan and re-scan.
- Not verified here: a real ZAP scan against the Compose dev target. This host has no Docker; ZAP is covered by a scripted client plus recorded alert/message fixtures.

Next: sanitizer and the AI layer.

## 2026-11-24 — Phase 3: scan manager and Nmap

- Scan API: request (202), list with pagination, detail, cancel and raw output download; one queued/running scan per assessment (409).
- Scan manager: in-process asyncio jobs, per-profile timeouts, Nmap concurrency semaphore, global ZAP lock, progress, cancellation, and startup recovery that fails queued/running scans with `interrupted by restart`.
- Scope guard runs at request time and again when the job starts, using the stored canonical target.
- Nmap runner uses fixed argv lists only (no shell, no client arguments), `-sT` profiles and host timeouts; XML is parsed with `defusedxml` behind a 50 MB cap.
- Raw tool output stored under `DATA_DIR/evidence/{assessment_id}/{scan_id}/` with SHA-256 and tool version; downloads resolve inside `DATA_DIR`.
- Recon endpoint aggregates completed Nmap scans by host, merges ports/services and reports per-scan parse errors.
- Tests: Nmap XML fixture/parser (including entity-expansion rejection), scan lifecycle, authorization/scope refusal, 422 validation, one-active-scan, cancel, execution-time re-check, restart recovery, raw download, recon aggregation.
- App start check: `create_app()` OpenAPI generation (18 paths) and lifespan health check pass locally.
- Not verified here: a real Nmap run against the Compose dev target. This host has neither Docker nor Nmap; the runner is covered by a fake runner plus parser fixtures.

Next: ZAP integration and the finding normalizer.

## 2026-11-23 — Phase 2: assessments, scope and scope guard

- Assessment CRUD, authorization confirmation, archive.
- Scope item CRUD with canonicalisation (host, IP, CIDR, URL prefix, port).
- Scope guard: fail-closed parsing (userinfo, decimal/octal/hex IP, dot segments, percent-encoding), DNS resolution with injected resolver, network allowlist, out-of-scope precedence, all-address coverage for CIDR scopes, Nmap port rules, ZAP include/exclude context.
- Dry-run `/scope/check` returns verdict + reasons and is audited; scans will reuse the same guard at execution time.
- Tests: 30+ table-driven scope cases and API tests.

Next: scan manager and Nmap.

## 2026-11-23 — Phase 1: auth and users

- JWT login (`/auth/login`, `/auth/me`), argon2 hashes, pinned HS256.
- In-memory login backoff per email+IP; generic invalid-credential errors.
- Admin user management (create/list/patch), role checks, self-lockout and last-admin guards.
- First-admin bootstrap from environment in the app lifespan and `scripts/seed.py`.
- Audit rows for login and user changes.
- Tests: login success/failure/inactive/expired token, rate limit, role enforcement, admin lifecycle.

Next: assessments, scope items and the scope guard.

## 2026-11-23 — Phase 0: scaffolding

- Repository layout, `docs/`, root `.env.example`, `.gitignore`.
- Backend package skeleton: config, logging, error handling, health endpoint.
- Dockerfile (nmap + WeasyPrint libs), Docker Compose (db, backend, zap, dev target, optional ollama).
- Alembic initialised; pytest + ruff configured.

Next: auth and users.
