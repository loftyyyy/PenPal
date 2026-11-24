# API changes since Phase 8

This file tracks contract changes for the frontend. Generated schema:
`docs/openapi.json` (`python scripts/export_openapi.py` from `Backend/`).

## Phase 9 — contract changes

- `PATCH /findings/{id}/verify` now requires `likelihood` and `impact` (1–5) for
  `confirmed`. The server computes `final_severity` from the matrix.
- `final_severity` is read-only. Sending it to the verify endpoint returns `422`.
- New `GET /api/v1/meta/severity-matrix` (authenticated) returns scales, labels and
  inclusive thresholds:
  - 20–25 critical, 12–19 high, 6–11 medium, 3–5 low, 1–2 informational.
- Confirm verification accepts an AI remediation when `final_remediation` is omitted;
  if no AI remediation exists, the request returns `422`.
- New `GET /api/v1/evidence/{id}/download` (authenticated, attachment).
  `EvidenceOut` adds `has_file` and `download_url`.
- `GET /assessments/{id}/audit-log` adds filters `action`, `entity_type`, `user_id`,
  `outcome` (`allowed`/`denied`), `from`, `to`.
- New `GET /assessments/{id}/audit-log/export?format=csv|json`.
- Dashboard fields changed:
  - `severity_confirmed` (final severity, confirmed findings only).
  - `severity_unverified` with `ai`, `tool` and `total` breakdowns.
  - `status_counts` replaces `verification_counts`.
  - `category_counts` is now `{confirmed, unverified}`.
  - `false_positive` is excluded from all severity and category breakdowns.
- `FindingOut` adds `likelihood` and `impact`.

## Phase 10 — tools

- `ScanTool` adds `dig`, `whois`, `whatweb`, `curl` and `http_checks`.
- `dig`, `whois`, `whatweb`, `curl` profiles: `default`. `http_checks` profiles:
  `config_baseline`, `session`, `access_control`, `auth_limited`.
- `whois` is skipped for private/internal targets and completes with a note.
- Raw output for these tools is text/JSON and stored like Nmap/ZAP output.
- `GET /assessments/{id}/recon` adds `dns`, `whois`, `technologies` and `http` sections.
- `FindingSource` adds `whatweb` and `http_checks`.

## Phase 11 — HTTP checks

- New `GET/PUT /assessments/{id}/http-check-config`.
- New `GET/POST /assessments/{id}/test-accounts` and
  `DELETE /assessments/{id}/test-accounts/{id}`. Passwords are write-only.
- New endpoint `GET /evidence/{id}/download`; `EvidenceOut` adds `has_file` and
  `download_url`.
- `ScanCreate` adds `confirm_lockout_test` (default false).

## Phase 12 — AI and summaries

- New `POST /assessments/{id}/summary/generate`, `GET /assessments/{id}/summary`,
  `PATCH /summaries/{id}`, `POST /summaries/{id}/approve`.
- Old ad-hoc `/analyze-summary` and `/ai-summary` are not part of the final contract;
  use the summary workflow.
- `AIAnalysisOut` adds `assessment_id` and `attempts` (attempt chain).
- `POST /findings/{id}/analyze` adds `?force=true`.
- Bulk analysis body adds `force`.
- Dashboard `ai_summary` is the approved summary only.
- Report uses the approved summary; drafts go to the AI appendix.

## Phase 13 — smoke

- New `scripts/smoke_e2e.py` (live stack only, not pytest).
- Compose `lsrs` placeholder and `LSRS_BASE_URL` TODO.
- Audit log export and filters documented in Phase 9.
