# Frontend progress

## Phase 0: scaffolding (done)
Vite + React, Tailwind v4, React Router, Axios, Recharts, Lucide. Folder structure and `.env` set up.

<<<<<<< HEAD
## 2026-11-25 — NVIDIA model chain and authorized public target

- OpenAI-compatible provider supports per-provider temperature, `top_p`, max tokens, extra request body and reasoning-content fallback.
- Primary candidate `nvidia/nemotron-3-ultra-550b-a55b` with `chat_template_kwargs.enable_thinking=true`; fallback `google/gemma-4-31b-it` with its own token budget (1024) and timeout (120s).
- Live probe: primary OK ~2–7s; Gemma fallback OK ~9–60s but timed out in later probes at 120s. Faster tested fallback candidates: `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning` (~1s) and `meta/muse-glimmer-30b` (~15s).
- Added `scripts/check_ai_models.py` (live only, never prints keys), `AI_*` request controls, and unit tests for extra body, reasoning content and fallback token budget.
- Public targets now require both `ALLOW_PUBLIC_TARGETS=true` and an exact host in `ALLOWED_PUBLIC_TARGETS`; the team-authorized deployed LSRS host is prefilled as a commented/default allowlist value, but the switch stays false by default.
- `PROJECT_CONTEXT.md` §14 records the narrow authorized-LSRS exception. All other public targets remain blocked.

## 2026-11-24 — Follow-up Phase 13: smoke test and handover
=======
## Phase 1: authentication and layout (done)
- Login page with validation and backend error display
- `authService` (login, me, logout), `AuthContext` (session restore via `/auth/me`, auto-logout on token expiry or any 401)
- `ProtectedRoute` and `AdminRoute`
- Sidebar (collapsible, mobile drawer), top bar (title, user, role, logout), role-based nav
- Placeholder pages for the remaining modules
>>>>>>> frontend

## Next: Phase 2, assessments
List, create, edit, details, confirm authorization, archive. Details page also needs scope items and scans.
