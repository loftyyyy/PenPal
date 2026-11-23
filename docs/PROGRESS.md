# PenPal backend progress

Newest entry first. Each phase ends with tests, a running app check, and a commit.

## 2026-11-23 — Phase 0: scaffolding

- Repository layout, `docs/`, root `.env.example`, `.gitignore`.
- Backend package skeleton: config, logging, error handling, health endpoint.
- Dockerfile (nmap + WeasyPrint libs), Docker Compose (db, backend, zap, dev target, optional ollama).
- Alembic initialised; pytest + ruff configured.

Next: auth and users.
