# PenPal

AI-assisted security assessment and vulnerability analysis platform for authorized,
local testing. PenPal wraps Nmap and OWASP ZAP, normalizes their output into findings,
offers advisory AI explanations and remediation, and requires a human assessor to
confirm every finding.

**Read `PROJECT_CONTEXT.md` first.** It is the source of truth for scope, ethics and
what the product must never do.

## Status

Backend under active development. See `docs/PROGRESS.md` and `docs/DECISIONS.md`.

## Quick start

```bash
cp .env.example .env
# edit .env: set SECRET_KEY, FIRST_ADMIN_PASSWORD and ZAP_API_KEY
docker compose up --build
```

- API: http://localhost:8000/api/v1/health
- Docs (development only): http://localhost:8000/docs
- PostgreSQL and ZAP are **not** published to the host.

With the demo target:

```bash
docker compose --profile dev-target up --build
```

The stand-in target (OWASP Juice Shop) is reachable from the backend as
`http://target:3000`. Add exactly that URL/host to an assessment's scope. This is a
stand-in for the Love & Styles Rental System test copy; see the comment in
`docker-compose.yml` before swapping it.

## Local development

Python 3.12 is used in the container; 3.11+ works for tests.

```bash
cd Backend
python -m venv .venv
.venv/Scripts/activate      # Windows; source .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
pytest
ruff check .
```

Tests use SQLite and fakes; they never call ZAP, Nmap, scan targets or an AI provider.

## Migrations

```bash
cd Backend
alembic upgrade head
alembic revision --autogenerate -m "describe change"
```

The container runs `alembic upgrade head` before starting uvicorn.

## Seed data

```bash
cd Backend
python scripts/seed.py --admin-only   # bootstrap first admin from environment
python scripts/seed.py --demo         # bootstrap admin plus a demo assessment
```

## AI providers

Set `AI_PROVIDER=mock` for tests and demos without a network. For a real provider use
`AI_PROVIDER=openai_compat` with an OpenAI-compatible base URL:

| Provider | `AI_BASE_URL` | Notes |
|---|---|---|
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai` | free tier available; prompts may be retained by the provider |
| Groq | `https://api.groq.com/openai/v1` | |
| OpenRouter | `https://openrouter.ai/api/v1` | |
| local Ollama | `http://ollama:11434/v1` | `AI_API_KEY` can be any non-empty string |

`AI_MODEL` is required for `openai_compat`; no model name is hard-coded. All AI input
is redacted first and the exact sanitized payload is stored in `ai_analyses`.

## Ethical rules

Scan only the authorized local target, never public websites or campus networks. The
scope guard rejects public IPs even when entered as in scope, and ZAP runs with a
context built from the same rules. See `PROJECT_CONTEXT.md` §14.
