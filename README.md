# PenPal

AI-assisted security assessment and vulnerability analysis platform for **authorized,
local** testing. PenPal wraps Nmap and OWASP ZAP, normalizes their output into findings,
offers advisory AI explanations and remediation, and requires a human assessor to
confirm every finding.

**Read `PROJECT_CONTEXT.md` first.** It is the source of truth for scope, ethics and
what the product must never do.

## Status

Backend complete for the course phases. See `docs/PROGRESS.md` for what was built and
`docs/DECISIONS.md` for non-obvious choices.

## Quick start

```bash
cp .env.example .env
# edit .env: set SECRET_KEY, FIRST_ADMIN_PASSWORD and ZAP_API_KEY
docker compose --profile dev-target up --build
```

- API health: http://localhost:8000/api/v1/health
- OpenAPI/Swagger (development only): http://localhost:8000/docs
- The container runs `alembic upgrade head` and the first-admin bootstrap on start.
- PostgreSQL and ZAP are **not** published to the host.

The `dev-target` profile starts OWASP Juice Shop as a stand-in for the LSRS test copy.
From the backend it is `http://target:3000`. Add exactly that host/URL to the
assessment scope. See the comment in `docker-compose.yml` before swapping the real
LSRS copy.

## Local development

Python 3.12 is used in the container; 3.11+ works for tests.

```bash
cd Backend
python -m venv .venv
.venv/Scripts/activate      # Windows; source .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
pytest
ruff check app tests
```

Tests use SQLite and fakes. They never call ZAP, Nmap, scan targets or an AI provider.

## Migrations and seed data

```bash
cd Backend
alembic upgrade head
alembic revision --autogenerate -m "describe change"

python scripts/seed.py --admin-only   # bootstrap first admin from environment
python scripts/seed.py --demo         # admin plus an idempotent demo assessment
```

`--demo` creates an authorized LSRS stand-in assessment with in/out-of-scope rules,
two completed scans, four confirmed findings, one pending, one false positive, one
needs-retest item, evidence, and one AI analysis. Re-running it is a no-op.

## Configuration

Copy `.env.example` to `.env`. The important variables:

| Variable | Purpose |
|---|---|
| `ENV` | `development`, `test` or `production`. Production refuses placeholder secrets. |
| `SECRET_KEY` | JWT signing key; at least 32 characters in production. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access-token lifetime, default 60. |
| `DATABASE_URL` | `postgresql+asyncpg://...` in Compose; SQLite in tests. |
| `DATA_DIR` | Raw scans, evidence uploads and reports. |
| `FIRST_ADMIN_EMAIL`, `FIRST_ADMIN_PASSWORD` | First administrator bootstrap. |
| `CORS_ORIGINS` | Comma-separated frontend origins; no wildcard. |
| `ZAP_BASE_URL`, `ZAP_API_KEY` | Internal ZAP daemon and API key. |
| `ZAP_TIMEOUT_SECONDS`, `ZAP_POLL_INTERVAL_SECONDS` | ZAP request and polling limits. |
| `ZAP_MAX_ALERTS`, `ZAP_ALERT_PAGE_SIZE` | Alert export bounds. |
| `ZAP_MAX_MESSAGE_FETCHES`, `ZAP_MESSAGE_MAX_CHARS` | HTTP evidence sampling limits. |
| `ZAP_ACTIVE_*` | Conservative active-scan limits. |
| `ALLOWED_TARGET_NETWORKS` | IP allowlist; default loopback and private ranges. |
| `ALLOW_PUBLIC_TARGETS` | Keep `false`; public targets are refused even if scoped. |
| `NMAP_MAX_CONCURRENCY` | Parallel Nmap jobs. |
| `SCAN_TIMEOUT_*_SECONDS` | Per-tool/profile hard timeouts. |
| `AI_PROVIDER` | `mock` or `openai_compat`. |
| `AI_BASE_URL`, `AI_API_KEY`, `AI_MODEL` | OpenAI-compatible provider settings. |
| `AI_MAX_RPM`, `AI_MAX_CONCURRENCY` | Provider rate limits. |
| `AI_MAX_EVIDENCE_CHARS` | Evidence budget sent to the model. |
| `MAX_UPLOAD_BYTES` | Manual evidence file cap (default 5 MB). |
| `REPORT_EVIDENCE_MAX_CHARS` | Evidence excerpt cap in reports. |

## Severity model

Final severity is **server-computed** from the assessor's likelihood and impact
(1–5 each). Clients cannot send `final_severity`.

| Score | Severity |
|---|---|
| 20–25 | critical |
| 12–19 | high |
| 6–11 | medium |
| 3–5 | low |
| 1–2 | info |

`GET /api/v1/meta/severity-matrix` returns the scales, labels and thresholds. Dashboard
severity counts are split into **confirmed** and **unverified** (AI-suggested or tool
severity); false positives are excluded from severity counts. Reports count confirmed
findings only.

## AI providers

`AI_PROVIDER=mock` is deterministic and needs no network; use it for tests and demos.
For a real chain use `AI_PROVIDER=openai_compat` with a primary and an optional fallback:

| Role | Variables | Example base URL |
|---|---|---|
| Primary | `AI_BASE_URL`, `AI_API_KEY`, `AI_MODEL` | Google Gemini: `https://generativelanguage.googleapis.com/v1beta/openai` |
| Fallback | `AI_FALLBACK_BASE_URL`, `AI_FALLBACK_API_KEY`, `AI_FALLBACK_MODEL` | OpenRouter: `https://openrouter.ai/api/v1` |
| Optional local | same variables, primary or fallback | Ollama: `http://ollama:11434/v1` |

The fallback is called only after a primary provider failure. Model names are environment
variables and are never hard-coded. Free models may be rate-limited, change or disappear.
Results are cached by prompt hash + prompt version across providers; use `?force=true`
to bypass the cache.

AI has three functions: `interpret`, `remediate`, and `summarize`. Findings receive only
`ai_suggested_severity`; AI never sets final severity or verification state. Summaries are
draft/approved records: only an approved summary appears in the report body; unapproved
drafts sit in the AI appendix. With zero confirmed findings, the server writes a
deterministic summary and does not call the provider.

All AI input is redacted first; the exact sanitized prompt and validated output are stored
in `ai_analyses`, including the provider attempt chain.

## API overview

All routes are under `/api/v1`. See `/docs` for the full OpenAPI schema.

| Area | Endpoints |
|---|---|
| Health | `GET /health`, `GET /health/dependencies` |
| Metadata | `GET /meta/severity-matrix` |
| Auth | `POST /auth/login`, `GET /auth/me` |
| Users (admin) | `POST /users`, `GET /users`, `PATCH /users/{id}` |
| Assessments | `POST/GET /assessments`, `GET/PATCH /assessments/{id}`, `POST /assessments/{id}/confirm-authorization`, `POST /assessments/{id}/archive` |
| Scope | `POST/GET /assessments/{id}/scope-items`, `DELETE /assessments/{id}/scope-items/{item_id}`, `POST /assessments/{id}/scope/check` |
| Scans | `POST/GET /assessments/{id}/scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /scans/{id}/raw` |
| Recon | `GET /assessments/{id}/recon` |
| Findings | `GET/POST /assessments/{id}/findings`, `GET /findings/{id}`, `PATCH /findings/{id}/verify`, `POST/GET /findings/{id}/evidence`, `GET /evidence/{id}/download` |
| HTTP checks | `GET/PUT /assessments/{id}/http-check-config`, `GET/POST /assessments/{id}/test-accounts`, `DELETE /assessments/{id}/test-accounts/{id}` |
| AI | `POST /findings/{id}/analyze`, `POST /assessments/{id}/analyze`, `GET /assessments/{id}/ai-status`, `GET /findings/{id}/ai-analyses` |
| Summaries | `POST /assessments/{id}/summary/generate`, `GET /assessments/{id}/summary`, `PATCH /summaries/{id}`, `POST /summaries/{id}/approve` |
| Dashboard | `GET /assessments/{id}/dashboard` |
| Reports | `POST/GET /assessments/{id}/reports`, `GET /reports/{id}/download` |
| Audit | `GET /assessments/{id}/audit-log`, `GET /assessments/{id}/audit-log/export?format=csv\|json` |

Scan tools: `nmap`, `zap`, `dig`, `whois`, `whatweb`, `curl`, `http_checks`.
`http_checks` profiles: `config_baseline`, `session`, `access_control`,
`auth_limited`. Test-account passwords are write-only and encrypted with
`CREDENTIALS_KEY`.

## End-to-end demo flow

After `docker compose --profile dev-target up --build` and
`docker compose exec backend python scripts/seed.py --demo`, or against a fresh stack:

```bash
BASE=http://localhost:8000/api/v1
TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@penpal.local","password":"CHANGE_ME-admin-password"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
AUTH="Authorization: Bearer $TOKEN"

# 1. Register and authorize an assessment.
ASSESSMENT=$(curl -s -X POST "$BASE/assessments" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name":"Demo","target_name":"LSRS stand-in","target_base_url":"http://target:3000","owner_name":"Demo owner","authorization_reference":"authorization.pdf"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -s -X POST "$BASE/assessments/$ASSESSMENT/scope-items" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"kind":"host","value":"target"}'
curl -s -X POST "$BASE/assessments/$ASSESSMENT/confirm-authorization" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"note":"Authorization checked"}'

# 2. Nmap, then ZAP baseline (one scan at a time per assessment).
NMAP=$(curl -s -X POST "$BASE/assessments/$ASSESSMENT/scans" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"tool":"nmap","profile":"quick","target":"target","ports":[3000]}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')
curl -s "$BASE/scans/$NMAP" -H "$AUTH"          # poll until status=completed

ZAP=$(curl -s -X POST "$BASE/assessments/$ASSESSMENT/scans" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"tool":"zap","profile":"baseline","target":"http://target:3000/"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')
curl -s "$BASE/scans/$ZAP" -H "$AUTH"           # poll until status=completed

# 3. Analyze all findings with the configured provider.
curl -s -X POST "$BASE/assessments/$ASSESSMENT/analyze" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"only_unanalyzed":true}'
curl -s "$BASE/assessments/$ASSESSMENT/ai-status" -H "$AUTH"

# 4. Verify one finding; only confirmed findings enter the report.
FINDING=$(curl -s "$BASE/assessments/$ASSESSMENT/findings?page_size=1" -H "$AUTH" \
  | python -c 'import json,sys; print(json.load(sys.stdin)["items"][0]["id"])')
curl -s -X PATCH "$BASE/findings/$FINDING/verify" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"decision":"confirmed","likelihood":4,"impact":4,"final_remediation":"Apply the vendor fix."}'

# 5. Generate and approve a summary, dashboard, report, download.
SUMMARY=$(curl -s -X POST "$BASE/assessments/$ASSESSMENT/summary/generate" -H "$AUTH" \
  | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -s -X POST "$BASE/summaries/$SUMMARY/approve" -H "$AUTH"
curl -s "$BASE/assessments/$ASSESSMENT/dashboard" -H "$AUTH"
REPORT=$(curl -s -X POST "$BASE/assessments/$ASSESSMENT/reports" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"format":"html"}' | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -s -L "$BASE/reports/$REPORT/download" -H "$AUTH" -o report.html
```

Use `"format":"pdf"` for PDF. If WeasyPrint cannot render on the host for a local run,
the API keeps a ready HTML report and returns `pdf_fallback=true`; the container installs
the required Pango/Cairo libraries.

## Smoke test

On a Docker host, after the stack and demo target are running:

```bash
cd Backend
python scripts/smoke_e2e.py --target http://target:3000
```

It logs in, creates and authorizes an assessment, runs Nmap, dig, whois (expects a
private-target skip), WhatWeb, ZAP baseline and HTTP config checks, analyzes findings,
verifies several with likelihood/impact, generates and approves a summary, checks the
dashboard and audit trail, generates a PDF and asserts it starts with `%PDF`. It exits
non-zero on the first failure. It is not part of `pytest`.

## What tools do on localhost targets

- Nmap and ZAP work normally against the in-scope local/Compose target.
- dig uses the system resolver only; no custom `@server` and no zone transfers.
- whois is skipped for private/internal targets, so it normally completes with a note
  instead of making an external registry lookup.
- WhatWeb runs at aggression 1 and does not follow redirects.
- `http_checks` uses httpx, not a shell curl command. It enforces the scope guard on
  every request and redirect, plus request, rate and login-attempt budgets.

## Security notes

- Every scan re-checks authorization and scope at execution time. Out-of-scope rules
  beat in-scope rules, DNS is resolved, and public IPs are denied by default.
- ZAP gets the scope guard's include/exclude context, so spider and active scans cannot
  wander to other hosts via links or redirects.
- Passwords use argon2; JWTs are short-lived and algorithm-pinned; login attempts are
  throttled in-process.
- AI input is redacted for cookies, authorization headers, tokens, keys, passwords,
  query values, userinfo/hosts, email, phones, cards and IPs. Target data is delimited
  as untrusted, output is schema-validated, and AI cannot set final fields.
- Uploads are size-capped, extension/MIME/signature checked, stored under random names,
  and downloads resolve inside `DATA_DIR`.
- Test-account passwords are encrypted with `CREDENTIALS_KEY`, write-only in the API,
  and redacted by exact match from evidence before AI/report use.
- Every HTTP-check request and redirect re-enters the scope guard and is audited with an
  allowed/denied outcome; methods and request/login budgets are capped.
- API responses set security headers and `no-store`; `/docs` is disabled in production.
- Production startup refuses placeholder or weak secrets.

## Known limitations

- Backend only; the frontend is a separate deliverable.
- Single backend process: scan and bulk-AI progress are in memory. A restart marks
  queued/running scans failed with `interrupted by restart`.
- `http_checks` implements a conservative subset: configuration baseline, cookie flags,
  access-rule replay, user enumeration and weak test-account passwords. Lockout testing
  only runs when explicitly confirmed; idle-timeout and post-logout replay remain manual.
- IDOR sample-ID templating is not implemented; the cut list in the follow-up prompt
  allowed dropping it.
- Real Nmap/dig/whois/WhatWeb/ZAP/HTTP-check/PDF execution is verified in the Compose
  container; this development host has no Docker and no Nmap/dig/WhatWeb. WeasyPrint's
  system libraries may also be absent locally.
- The exact LSRS address and final Gemini/OpenRouter model names remain environment
  decisions. The public deployed LSRS URL is not enabled: public targets stay blocked
  by §14 of `PROJECT_CONTEXT.md` until the team records explicit authorization there.

## Layout

```text
Backend/
  app/
    api/v1/            thin routers
    core/              config, logging, errors, JWT, middleware
    db/                SQLAlchemy models and session
    schemas/           Pydantic request/response models
    services/          scope guard, scans, normalizer, sanitizer, AI, findings,
                       verification, evidence, dashboard, report builder
    templates/         report.html.j2
  alembic/
  scripts/seed.py
  tests/
docs/                  PROGRESS.md, DECISIONS.md
docker-compose.yml
.env.example
```
