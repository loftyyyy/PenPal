# Decisions

One line per non-obvious decision: what was chosen and why.

- Keep the existing `Backend/` directory name instead of creating `backend/`; the checkout already had `Backend/` and `Frontend/`.
- Use integer primary keys everywhere; simple, portable and easy to read in URLs.
- Use SQLAlchemy async sessions with asyncpg in Docker and aiosqlite in tests; one code path, async tool calls.
- Verification state is `false_positive`, not `rejected`: `PROJECT_CONTEXT.md` §18 makes this authoritative over the task prompt, which uses `rejected`.
- Two AI functions only (`interpret`, `remediate`) as the task prompt requires; `PROJECT_CONTEXT.md` also lists a summary function — see the final report's open questions.
- Hypothesis: host scope rules match one exact host; `*.example.test` is the explicit subdomain wildcard. Default deny.
- A URL is allowed when its host has an exact in-scope host/IP/CIDR rule; when a host is scoped only through `url_prefix` rules, the path must match a prefix on a boundary (`/admin` does not match `/administrator`).
- Out-of-scope rules always win over in-scope rules, including across hosts resolved from the same DNS name.
- Ambiguous numeric hosts (decimal, hex, octal IP forms, non-canonical IPv4) are rejected, not normalised, to avoid parser-confusion bypasses.
- Docker-internal service names are allowed because they resolve into the configured private networks; the allowlist is IP-based.
- ZAP image pinned to `zaproxy/zap-stable:2.17.0` (current stable tag verified on Docker Hub on 2026-11-23).
- Reports use Jinja2 autoescape; PDF rendering is attempted at generation time and failure does not destroy the HTML report.
- All timestamps are stored in UTC with `created_at`/`updated_at` on every table; `audit_log` is append-only by contract.
- Scan jobs are in-process `asyncio` tasks (no Celery/Redis) and the API returns `202` immediately; this assumes one backend process, which the Compose stack runs.
- Nmap targets are stored as a bare host. An explicit port in a URL becomes the port filter so the profile cannot silently widen the scan; the scope guard re-checks that stored canonical target at execution time.
- The one-active-scan-per-assessment limit is a DB check in the service; the single-process assumption makes the remaining request race acceptable for this project.
- Raw evidence paths are built from generated assessment/scan IDs only, and every download resolves under `DATA_DIR`.
- Recon merges by host address: an open observation wins over closed, service detail is filled from later scans, and an unreadable scan XML is reported per scan instead of failing the endpoint.
