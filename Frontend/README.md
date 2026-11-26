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

## Backend contract deviations found while building

- `POST /findings/{id}/analyze` returns `{ finding_id, analyses: AIAnalysisOut[] }`.
  `BACKEND_CONTEXT.md` names `FindingAnalysisOut` but does not define it.
- Admin user updates for self-lockout / last-admin return `422` with
  `self_lockout` / `last_admin`, not the `409` listed in the error matrix.
- With zero confirmed findings, summary generation stores a deterministic summary
  instead of returning `409 no_confirmed_findings` (the endpoint description and the
  error matrix disagree).
