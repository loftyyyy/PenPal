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

- `ScanTool` adds `dig`, `whois`, `whatweb` (profiles: `default`).
- `whois` is skipped for private/internal targets and completes with a note.
- Raw output for these tools is text/JSON and stored like Nmap/ZAP output.
- `GET /assessments/{id}/recon` adds DNS, WHOIS, technology and HTTP-check sections
  (see the current schema).

## Later phases

- AI provider failover, attempt-chain fields and assessment-summary workflow are
  documented here when their phase lands.
