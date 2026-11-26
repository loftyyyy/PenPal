# PenPal Frontend

React + TypeScript (Vite) client for the PenPal API. The contract lives in
[`../BACKEND_CONTEXT.md`](../BACKEND_CONTEXT.md); `src/lib/types.ts` mirrors it.

## Run

```bash
npm install
npm run dev
```

`VITE_API_BASE_URL` defaults to `http://localhost:8000/api/v1`. Copy
`.env.example` to `.env.local` only when you need a different backend. The backend
allows `http://localhost:5173` by default.

`vite.config.ts` proxies `/api` to `http://127.0.0.1:8000`. Setting
`VITE_API_BASE_URL=/api/v1` is useful when port 5173 is occupied or when serving
through the dev proxy.

## Verify

```bash
npm run typecheck
npm test
npm run build
```

## Notes

- The token is kept in `sessionStorage` (tab-scoped) and sent as a bearer token.
  There is no refresh endpoint; a `401` clears the session and redirects to login.
- Scans and bulk AI are polled; reports are synchronous.
- Downloads (raw scan output, evidence, reports, audit exports) use bearer auth and
  the `Content-Disposition` filename.
- Final severity is read-only and computed by the server from likelihood × impact.
- AI severity and remediation are labelled advisory throughout.
- Light/dark/system theme is persisted in `localStorage`; system is the default.
- `Field` links labels to controls; all action buttons are keyboard reachable.
- The authorization file picker records only the selected file name; the backend has
  no assessment-file upload endpoint. Creating or replacing the file chains
  `PATCH /assessments/{id}` with `POST /assessments/{id}/confirm-authorization`.
- First-run onboarding and the assessment workflow checklist use local browser state
  and live assessment/scope/dashboard data.
- Component tests use Vitest + Testing Library (`jsdom`).

## Backend contract deviations found while building

- Admin user updates for self-lockout / last-admin return `422` with
  `self_lockout` / `last_admin`, not the `409` listed in the error matrix.
- `BACKEND_CONTEXT.md` line 1302 lists `409 no_confirmed_findings` for summary
  generation, but the endpoint and summary service store a deterministic summary.
