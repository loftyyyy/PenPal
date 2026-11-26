# Frontend progress

## Phase 0: scaffolding (done)
Vite + React, Tailwind v4, React Router, Axios, Recharts, Lucide. Folder structure and `.env` set up.

## Phase 1: authentication and layout (done)
- Login page with validation and backend error display
- `authService` (login, me, logout), `AuthContext` (session restore via `/auth/me`, auto-logout on token expiry or any 401)
- `ProtectedRoute` and `AdminRoute`
- Sidebar (collapsible, mobile drawer), top bar (title, user, role, logout), role-based nav
- Placeholder pages for the remaining modules

## Next: Phase 2, assessments
List, create, edit, details, confirm authorization, archive. Details page also needs scope items and scans.
