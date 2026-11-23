# PenPal backend progress

Newest entry first. Each phase ends with tests, a running app check, and a commit.

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
