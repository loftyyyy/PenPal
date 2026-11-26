# PenPal backend progress

Newest entry first. Each phase ends with tests, a running app check, and a commit.

## 2026-11-25 — NVIDIA model chain and authorized public target

- OpenAI-compatible provider supports per-provider temperature, `top_p`, max tokens, extra request body and reasoning-content fallback.
- Primary candidate `nvidia/nemotron-3-ultra-550b-a55b` with `chat_template_kwargs.enable_thinking=true`; fallback `google/gemma-4-31b-it` with its own token budget (1024) and timeout (120s).
- Live probe: primary OK ~2–7s; Gemma fallback OK ~9–60s but timed out in later probes at 120s. Faster tested fallback candidates: `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning` (~1s) and `meta/muse-glimmer-30b` (~15s).
- Added `scripts/check_ai_models.py` (live only, never prints keys), `AI_*` request controls, and unit tests for extra body, reasoning content and fallback token budget.
- Public targets now require both `ALLOW_PUBLIC_TARGETS=true` and an exact host in `ALLOWED_PUBLIC_TARGETS`; the team-authorized deployed LSRS host is prefilled as a commented/default allowlist value, but the switch stays false by default.
- `PROJECT_CONTEXT.md` §14 records the narrow authorized-LSRS exception. All other public targets remain blocked.

## 2026-11-24 — Follow-up Phase 13: smoke test and handover

- `scripts/smoke_e2e.py` runs the full flow against a live stack (login, assessment, scope, authorization, Nmap, dig, whois skip, WhatWeb, ZAP, HTTP config checks, AI analysis, L×I verification, summary generation/approval, dashboard, PDF download, audit). It exits non-zero on failure and is excluded from pytest.
- Compose docs add the `lsrs` placeholder, `host.docker.internal` guidance and the rule that a host dev server bound to `127.0.0.1` is not reachable from containers. `LSRS_BASE_URL` is a TODO placeholder.
- README and `docs/API_CHANGES.md` updated for the follow-up contract. `PROJECT_CONTEXT.md` synced in Task 0.
- Not verified on this host: Docker build, real Nmap/dig/whois/WhatWeb/ZAP/HTTP checks, real Gemini/OpenRouter calls, WeasyPrint PDF. The smoke test is the team's acceptance gate for those.

## 2026-11-24 — Follow-up Phase 12: AI chain, summary workflow, report appendix

- Primary → fallback provider chain with bounded retries, circuit breaker (3 failures, 60s cooldown), attempt-chain persistence and provider-agnostic cache key. `?force=true` bypasses the cache.
- Third AI function `summarize` uses confirmed findings only, aggregates counts, endpoint paths and first-line remediation, and never receives raw evidence.
- Draft summary / edit / approve workflow in `assessment_summaries`; approval supersedes the previous approved summary. Zero confirmed findings produce a deterministic summary without an AI call.
- Report body uses only an approved summary; deterministic facts remain authoritative; unapproved drafts and pending/needs-retest AI suggestions appear in labelled appendices with UNVERIFIED markers.
- Tests cover failover, circuit breaker, attempt chain, force cache bypass, summary rules and report appendix behavior. Full suite: 255 passed.

## 2026-11-24 — Follow-up Phase 11: HTTP checks

- `http_checks` profiles: `config_baseline`, `session`, `access_control`, `auth_limited`, using httpx rather than a shell curl binary.
- Configuration and write-only test accounts: roles are configurable (default staff/admin, no customer role); passwords are Fernet-encrypted with `CREDENTIALS_KEY`, never returned or logged, and redacted by exact match from evidence before AI/report use.
- Every request and redirect re-enters the scope guard and is audited; methods are restricted, request/rate/login budgets are enforced, and redirects are followed manually with a cap.
- Findings cover headers/CORS/banners/error pages/cookies, role access mistakes and authentication weaknesses. Evidence includes a redacted request/response summary and a curl-equivalent command with placeholders.
- Tests use httpx MockTransport: baseline findings, session/access-control, user enumeration/weak password, out-of-scope redirect blocking, request budget, secret redaction and config/account API behavior.

## 2026-11-24 — Follow-up Phase 10: dig, whois, WhatWeb and HTTP recon

- Scan tools add `dig`, `whois`, `whatweb` (and a fixed `curl` fetch); dig uses the system resolver for A/AAAA/CNAME/MX/NS/TXT only.
- whois is skipped for private/internal targets with a completed scan note and no subprocess; WhatWeb runs at aggression 1, JSON output, no redirects.
- Raw output, hashes, cancellation, timeouts and scope checks reuse the scan manager. Recon adds DNS, WHOIS, technology and HTTP sections.
- WhatWeb explicit version banners become `info` findings with stable fingerprints. Tests use fake runners plus parser fixtures.

## 2026-11-24 — Follow-up Phase 9: contract changes

- Likelihood/impact 1–5 on findings; server computes final severity with the team's bands. `final_severity` is read-only; confirmed requires L/I; confirmation can accept an AI remediation with an audit entry.
- `GET /meta/severity-matrix`; dashboard now returns `severity_confirmed`, `severity_unverified` (ai/tool/total), `status_counts` and confirmed/unverified category counts. False positives are excluded from severity/category counts.
- Audit filters (`action`, `entity_type`, `user_id`, `outcome`, `from`, `to`) and CSV/JSON export with formula-injection escaping.
- Evidence file download adds hash/type checks and attachment disposition. `scripts/export_openapi.py` and `docs/API_CHANGES.md` added.

## 2026-11-24 — Phase 8: hardening and handover

- Security review: secrets only from environment with production refusal, argon2 passwords, HS256 pinned by config validator, login throttling, strict Pydantic inputs, ORM/bound queries, no shell, generated-ID file paths, upload allowlists/signatures, generic error bodies, request IDs and redacting logs.
- API responses now carry `Cache-Control: no-store` and a restrictive CSP on every `/api/*` response. ZAP health checks use the `X-ZAP-API-Key` header, so the key never appears in a URL.
- OpenAPI reviewed: 30 paths / 38 operations, every operation has a tag and summary, and key request bodies carry examples.
- `scripts/seed.py --demo` now creates an idempotent authorized demo assessment with scope rules, two scans, seven findings across all verification outcomes, evidence, one AI analysis, and realistic severities for dashboard/report demos. Verified against a migrated SQLite database; a second run is a no-op.
- `README.md` completed: stack, configuration table, local tests, migrations, seeding, AI provider table, endpoint overview, end-to-end curl flow, security notes, limitations and layout.
- Added `Backend/.dockerignore` and extra PDF runtime libraries (`libglib2.0-0`, `fontconfig`, `libharfbuzz-subset0`) to the image, plus package data for the report template.
- Final suite: 209 passed. Coverage: overall 81%, `sanitizer` 95%, `scope_guard` 86%, `verification` 98%, `finding_normalizer` 93%.
- App start check: OpenAPI generation (30 paths) and lifespan health check pass locally. `alembic upgrade head` and `seed.py --demo` pass against a temporary migrated SQLite database.
- Not verified here: Docker Compose build/up, a real Nmap/ZAP scan, a real hosted AI call, and WeasyPrint PDF rendering on this Windows host (missing system Pango/GTK). Tests use fakes, a mock provider and an injected PDF renderer; the container is the deployment target for those checks.

Next: handover. See `README.md`, `docs/DECISIONS.md` and the final report below.

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

## 2026-11-27 - Target authorization files and ZAP ingestion repair

- Target ownership tokens are stored in `authorization_files` with a unique random token, expiry (1-720 hours), revocation timestamp, verification timestamp and failure text.
- Management is limited to the assessment creator or an admin. Creating a new token revokes the previous active token for the same assessment/target.
- Verification fetches the assessment target's configured well-known path over http(s), follows no redirects, reads at most 4 KiB and compares the body exactly to the token.
- Root cause of missing `active_limited` findings: ZAP message bodies can contain binary data with NUL escapes. `json.loads` produced NUL characters, PostgreSQL JSONB rejected the insert (`0x00`), and the whole finding transaction rolled back after the scan had been marked completed.
- The normalizer now removes NUL characters from every persisted text and JSON value, including raw alerts and HTTP evidence, before the database write.
- Tests cover authorization ownership, expiry, revocation, mismatch, remote failure and token rotation. ZAP tests cover `active_limited` alerts with empty attack/evidence/param, CWE `-1`, Medium/Low/Informational risks, NUL response bodies, and dashboard/finding visibility.
- Live Docker verification: fresh ZAP `active_limited` scan completed with 233 findings; dashboard reported all 237 findings (233 ZAP + 4 HTTP checks).
