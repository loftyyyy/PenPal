# PenPal backend progress

Newest entry first. Each phase ends with tests, a running app check, and a commit.

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
