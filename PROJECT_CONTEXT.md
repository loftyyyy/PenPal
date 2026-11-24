# PenPal: AI-Assisted Security Assessment and Vulnerability Analysis Platform

> **Status:** v0.2 (2026-11-23), updated from the signed Project Proposal (Deliverable 1, signed 11-11-2026)
> **Course:** CS24L – 4755
> **Read this file first.** It is the single source of truth for what PenPal is, what it must do, and what it must never do. If code or a prompt conflicts with this file, this file wins. If this file looks wrong, flag it. Do not silently deviate.
> Items marked **⚠ OPEN** are unresolved or inconsistent in the proposal. See §17.

---

## 1. What PenPal is

PenPal is a web platform that helps a human **security assessor** run a structured, authorized security assessment of a web application. It does not replace existing tools and it is **not a new scanner**. It combines them with AI and a human verification workflow:

1. **Registers a target and enforces its scope.** A *scope guard* blocks any tool run or request outside the allowlist, rate-limits, and records every event (who, what, when, allowed or disallowed) in an audit log.
2. **Runs reconnaissance and scanning** using existing tools: **Nmap**, **dig**, **whois**, a technology fingerprinter (**WhatWeb**), **OWASP ZAP** (daemon, REST API), and **curl**/scripted requests. Raw outputs are saved as evidence.
3. **Normalizes outputs into findings** (title, category, endpoint, evidence, tool, raw output) in a common record.
4. **Uses AI** to explain findings, suggest severity, suggest remediation, and summarize confirmed results. AI always works on real tool output, and is never a general chatbot.
5. **Requires human verification.** The assessor marks each finding **Confirmed**, **False Positive**, or **Needs Retest**. Only **Confirmed** findings count as vulnerabilities and appear in the main report.
6. **Shows a dashboard** and **generates a PDF security assessment report.**

**Core principle: human in the loop.** AI can hallucinate, rate severity incorrectly, and be tricked by text planted in the target. Every AI output is a *suggestion*, labelled "AI-suggested" until an assessor acts on it. The final severity and remediation come from the assessor.

### Why it exists
Web apps expose many hosts, ports, endpoints, parameters, and settings. Testers juggle several tools, wade through thousands of lines of inconsistent output, deal with false positives and duplicates, and keep notes scattered across tools and screenshots with inconsistent risk labels. PenPal centralizes the outputs, speeds up triage and explanation with AI, and keeps the assessor accountable for what is reported.

---

## 2. Team and roles

| Member | Role | Main responsibilities |
|---|---|---|
| Airo S. Parondo | Project lead | Coordination, documentation, Docker/deployment |
| Charisse C. Priego | Frontend developer | Dashboard, findings, and report views |
| Rho Alphonce E. Jornadal | Backend and database | API, data model, tool integration |
| Jonathan G. Sindo | Security tester | Reconnaissance, scanning, verification, test cases |
| Gwendolyn Lianna P. Peralta | AI integration | AI functions, prompt design, data handling |

---

## 3. Objectives

**General objective:** To develop a platform that combines existing security tools with AI to assess an authorized web application, while keeping a human assessor in charge of which findings count as confirmed vulnerabilities.

**Specific objectives** (each must be demonstrable at the final presentation):

1. Register a target, define in-scope and out-of-scope assets, and **block any tool run outside that scope**, with every action recorded in an audit log.
2. Integrate **Nmap, DNS utilities, OWASP ZAP, and curl**, and bring their parsed outputs into one central dashboard.
3. Assess **at least three** web security categories and store each result with its supporting evidence.
4. Implement **at least two AI-assisted functions** (scan result interpretation and remediation suggestion) that work on real tool output.
5. Provide a verification workflow where the assessor confirms or rejects each AI-generated finding, so **only confirmed findings count as vulnerabilities**.
6. Classify findings by severity, recommend remediation, and generate a security assessment report containing findings, evidence, risks, and recommendations.

---

## 4. Target application (what PenPal assesses)

| Field | Value |
|---|---|
| Application name | **Love & Styles Rental System** (referred to as **LSRS**) |
| Description | Web-based system for managing gown rentals, customer records, gown inventory, reservations, rental transactions, and payments |
| Owner / authorizing person | Rho Alphonce Jornadal, Charisse Priego, Jonathan Sindo (the system's own developers) |
| Proof of authorization | Signed authorization letter, attached to the proposal as a separate PDF |
| Hosting environment | **Local machine**, local development environment, reached via `localhost` or an explicitly authorized local IP address |
| Test accounts | Administrator and staff accounts only. LSRS has no customer-facing role. Access checks cover unauthenticated, staff (where present) and admin principals; the role list is configurable. |
| Test data | Synthetic only: customer records, sample gown inventory, simulated reservations, rental transactions, payment records. No real customer data, no production credentials |

### Networking note for the engineers
LSRS runs on the developer's machine, while PenPal and its tools run in Docker. Inside a container, `localhost` means **the container itself**, not the host. To reach LSRS:
- use `host.docker.internal` (on Linux add `extra_hosts: ["host.docker.internal:host-gateway"]`), or the host's explicitly authorized LAN IP, or run LSRS as a container on the Compose network, and
- add **exactly that address** as the in-scope item. The scope guard must treat it as the target and still reject everything else.

The default network allowlist (loopback + private ranges) must keep working for these cases, and public IPs stay rejected.

---

## 5. Scope and limitations

**In scope**
- Locally hosted Love & Styles Rental System
- `localhost` or the explicitly authorized testing IP address
- Application ports and services approved for assessment
- Login and authentication pages
- Admin dashboard and staff dashboard
- Inventory management module
- Customer management module
- Reservation and rental management modules
- Payment management module
- User management and role-based access control
- Application forms, search fields, and other authorized input interfaces

**Out of scope (hard rules)**
- Public websites and third-party services
- University or campus networks
- Production systems and real customer databases
- External payment gateways and third-party integrations
- Any IP address, port, service, or application not explicitly authorized
- Destructive testing, denial-of-service, and attacks that may disrupt availability

**Limitations**
- Login testing is limited to a **small, rate-limited number of attempts against test accounts**. No large-scale brute force.
- Findings are limited to what the chosen tools and manual tests detect. No claim of full coverage.
- Local test environment with synthetic data, so results may differ from a production deployment.
- AI output depends on the model and can be wrong, hence mandatory assessor verification.
- Time: one semester, alongside other coursework. Actual milestone dates are in §15.

---

## 6. Security assessment categories (chosen: five)

| Category | What is tested |
|---|---|
| **Authentication and login security** | Password and lockout rules, failed-login error handling, default/weak credentials on test accounts, password reset procedure |
| **Access control and authorization** | Replaying requests as unauthenticated, staff (when present) and admin: staff must not reach admin pages or user management; records must not be readable by changing an ID in the URL (IDOR). Highest-risk area |
| **Input validation and injection** | Input and search fields in inventory, customer, reservation, and payment modules; SQL injection and XSS at **low intensity** via ZAP and manual checks |
| **Session management** | Session cookie flags, session timeout, logout behavior, reusing a session after logout (curl and browser dev tools) |
| **Security configuration and HTTPS** | HTTP security headers, cookie attributes, CORS, banners, error pages, and TLS configuration if HTTPS is enabled on the permitted host |

How the tooling maps: ZAP mostly covers input validation, configuration/headers, and some information disclosure. Authentication, session, and access-control checks rely on **curl/scripted requests with one test account per role** plus manual verification. This is why the human verification step matters.

---

## 7. How a user works with PenPal

1. **Login**, then create an **Assessment**: target name, base URL, host, port, owner/authorizing person, authorization reference, hosting environment.
2. **Define scope:** allowed hosts, IPs, and path prefixes, plus out-of-scope exceptions. Confirm authorization. Until then, scans are blocked.
3. **Reconnaissance:** run Nmap (XML output), dig, whois, and tech fingerprinting against the in-scope host. A parser produces hosts, open ports, services, and discovered endpoints for the **Recon page**.
4. **Scanning and assessment:** ZAP spider, passive scan, and a low-intensity active scan of forms and search fields. Curl/scripted requests with one test account per role check login results, session cookies, and access control. Raw output is stored as evidence.
5. **Findings** appear normalized (title, category, endpoint, evidence, tool, raw output), de-duplicated, on the **Findings page**.
6. **AI analysis** on *redacted* data: explanation, impact, affected component, suggested severity; OWASP/CWE mapping; remediation suggestions. Displayed as AI-suggested.
7. **Verification:** the assessor sees the finding with its evidence (raw tool output, response snippet, or screenshot) next to the AI suggestion, then chooses **Confirmed / False Positive / Needs Retest**, records name, notes, and timestamp, and keeps or changes the severity (likelihood × impact). The AI severity is displayed alongside the assessor's severity.
8. **Dashboard:** scan progress, findings by severity, type, category, and verification status, and the last scan.
9. **Report (PDF):** scope, methodology, tools; confirmed findings grouped by severity with evidence; risk overview; remediation advice; AI usage and limitations. **Unverified AI recommendations appear only in an appendix.**

---

## 8. Architecture

```
Assessor's browser
      │
      ▼
 React frontend ─────────► FastAPI backend  (the only component that talks to everything else)
                               │
   ┌────────────┬──────────────┼───────────────────┬───────────────────┐
   ▼            ▼              ▼                   ▼                   ▼
PostgreSQL   Tool runners    OWASP ZAP         AI provider         LSRS test target
(findings,   (containers/    (daemon, REST,    (Gemini free tier   (localhost / authorized
 scans,       workers: Nmap,  internal only)    default; local      local IP; reached via
 audit,       dig, whois,                       Ollama swappable)   the scope guard only)
 evidence)    WhatWeb, curl)
```

- Everything PenPal-owned runs in **Docker Compose** on an internal network. Only the backend and frontend are published. **ZAP's port and the database are never exposed.**
- Scans are long-running, so they run as **background workers**, with the API returning a scan ID immediately and clients polling status.
- **Scope enforcement lives in the backend.** Every tool run and every outbound request toward the target goes through the scope guard, which allows or blocks it, rate-limits, and audits it.
- Raw tool outputs are saved as evidence before any parsing.

---

## 9. Technology stack

| Component | Technology | Purpose |
|---|---|---|
| Frontend | React.js (Vite) | Dashboard, findings, verification, and report views |
| Backend | Python, FastAPI (SQLAlchemy, Alembic, Pydantic) | REST API, scope enforcement, tool orchestration |
| Database | PostgreSQL | Assessments, scans, findings, evidence, verification status, audit log |
| Security tool 1 | Nmap | Port, service, and version discovery (XML output) |
| Security tool 2 | OWASP ZAP (daemon mode) | Web vulnerability scanning through the REST API |
| Supporting tools | dig, whois, WhatWeb, `http_checks` (Python/httpx) | DNS/ownership info, technology fingerprinting, scripted auth/session/access-control/configuration checks |
| AI model / API | Google Gemini API (free tier) primary and OpenRouter free-tier fallback, failover only; local Ollama remains an optional OpenAI-compatible provider; mock provider for tests | Finding interpretation, remediation and summary |
| Reports | PDF generator (planned: Jinja2 + WeasyPrint) | Final assessment report |
| Deployment | Docker Compose on a local machine or Linux VM | Reproducible deployment |

---

## 10. Proposed features (as committed in the proposal)

- **Target and scope management:** save the target (name, base URL, host, port); create scope rules (allowed hosts, IPs, path prefixes; out-of-scope exceptions). The scope module prevents and records every out-of-allowlist request, enforces a rate limit, and audits each event (who, what, when, allowed/disallowed).
- **Reconnaissance and scanning:** background workers run Nmap (XML), dig, whois, and a tech fingerprinter against the in-scope host, each in a container, saving raw results as evidence. A parser produces hosts, open ports, services, and discovered endpoints for the Recon page.
- **Web application security assessment:** ZAP in daemon mode via REST (spider, passive scan, low-intensity active scan of forms and search fields). Curl and scripted requests with one test account per role examine login results, session cookies, and access control. Everything normalizes into a common **Finding** record.
- **AI integration:** three capabilities (§11).
- **Findings verification and risk assessment:** §7 step 7 and §12.
- **Dashboard and report generation:** §7 steps 8–9.

---

## 11. AI integration

None of these is a general chatbot. All take real tool output as input.

| AI function | Input | Output | Where it appears |
|---|---|---|---|
| **Interpreting scan results** | ZAP alert JSON, scan details, supporting evidence (redacted) | Plain-language explanation, potential impact, affected component, suggested severity (plus OWASP/CWE mapping) | Findings page |
| **Suggesting vulnerability remediation** | Vulnerability details, scan evidence, classification | Recommended fixes, mitigation steps, secure coding practices | Finding Details page, Remediation section |
| **Assessment summary generation** | **Confirmed findings only** | Executive summary and key risks in plain language | Final report and dashboard |

Remediation timing is decided: remediation is generated as a pre-verification AI suggestion, and may be re-run on a confirmed finding with the verified context. Confirmation can accept the existing AI remediation as-is, with an audit entry. Assessment summaries are drafts until the assessor approves them; only the approved summary is used in the report.

### AI data protection (non-negotiable)
- The model receives only what it needs: finding type, **relative endpoint path**, and a **brief evidence snippet**.
- Redaction happens **in the backend before any request leaves**: cookies, session tokens, `Authorization` headers, passwords, API keys, email addresses, and **internal IP addresses** are stripped. Test-account credentials used for role checks must never reach the AI, the logs, or the report.
- Target content is **untrusted input**. Prompts tell the model to treat it as data and ignore any instructions inside it. Model output is schema-validated.
- **All AI requests and responses are stored in the audit trail** (the exact redacted payload that was sent, plus the response).
- The AI module is swappable (Gemini free tier ⇄ local Ollama). Free hosted tiers may use prompts to improve their products, so assume anything sent is not private.
- AI never sets the final severity and never confirms a finding. If the AI is unavailable, the platform still works and the assessor triages manually.

---

## 12. Methodology and framework references

- **OWASP Web Security Testing Guide (WSTG):** test cases.
- **NIST SP 800-115:** planning, discovery, attack, and reporting phases.
- **Penetration Testing Execution Standard (PTES):** overall workflow.
- Findings are mapped to the **OWASP Top 10** and **CWE** identifiers.
- **Severity:** likelihood × impact, translated to **Critical, High, Medium, Low, Informational**, aligned with CVSS-style ratings. Decided bands: likelihood 1–5 × impact 1–5 → score 20–25 Critical, 12–19 High, 6–11 Medium, 3–5 Low, 1–2 Informational. The server computes final severity; clients cannot set it.

**Assessment process (maps to PenPal modules)**

| # | Stage | What happens in PenPal |
|---|---|---|
| 1 | Define Scope | Register the target, record the authorization, set in-scope/out-of-scope rules in the scope guard |
| 2 | Reconnaissance | Nmap, dig, whois, fingerprinting against the in-scope host: ports, services, endpoints |
| 3 | Scanning | ZAP spider and passive scan plus curl checks; raw output saved as evidence |
| 4 | Security Assessment | Chosen categories tested; normalized findings created |
| 5 | AI Analysis | Redacted evidence to the AI: explanation, severity suggestion, remediation, OWASP/CWE mapping |
| 6 | Findings Verification | Assessor reviews evidence and marks Confirmed / False Positive / Needs Retest, with notes and timestamp |
| 7 | Risk Assessment | Assessor finalizes severity (likelihood × impact) and remediation for each confirmed finding |
| 8 | Report Generation | PDF from confirmed findings; appendix for unverified AI suggestions; section on AI usage and limitations |

---

## 13. Core domain model (summary)

`User` (roles: admin, assessor) · `Assessment` · `ScopeItem` (in/out, host/IP/CIDR/path prefix/port) · `Scan` (tool, profile, status, raw output + hash) · `ReconResult` (hosts, ports, services, endpoints) · `Finding` · `Evidence` (raw output, response snippet, screenshot, note; with SHA-256) · `AIAnalysis` (function, provider, model, prompt version, redacted input, validated output) · `Verification` (decision, assessor, notes, timestamp; history preserved) · `Report` · `AuditLog` (append-only: scope allow/deny events, scans, AI calls, verifications).

**Finding fields (minimum):** title, category, endpoint, evidence, tool, raw output; plus OWASP Top 10 label, CWE, `tool_severity`, `ai_suggested_severity`, assessor `likelihood`, `impact`, `final_severity`, `final_remediation`, `verification_status`.

**Severity scale:** `critical`, `high`, `medium`, `low`, `info`.
**Verification states:** `pending` → `confirmed` | `false_positive` | `needs_retest`.
Tool severity, AI-suggested severity, and assessor (final) severity are **separate fields** and are never overwritten by each other. The UI shows AI and assessor severity side by side.

---

## 14. Ethical and safety rules (engineering constraints, not suggestions)

1. Test only applications authorized by the instructor or system owner.
2. Never scan public websites, university networks, or unauthorized systems. The backend **rejects** non-allowed targets even if someone enters them as "in scope". Exception (team decision, v0.3): the authorized deployed LSRS host may be tested only when its exact hostname is listed in `ALLOWED_PUBLIC_TARGETS`, `ALLOW_PUBLIC_TARGETS=true`, and written authorization is on file. All other public targets remain blocked.
3. Use test accounts and synthetic data only.
4. No destructive attacks, no DoS, nothing that may disrupt services. Scan profiles are fixed, low-intensity, and rate-limited. Login testing stays within a small number of attempts.
5. Never expose credentials or confidential information to AI services (§11).
6. Document testing and keep real technical evidence: raw outputs, timestamps, hashes, and an audit trail of every action and decision.
7. PenPal is itself a security tool, so it must be built securely: no shell injection, no secrets in logs, no exposed ZAP or database ports, no free-form tool arguments from clients.

---

## 15. Timeline (from the proposal)

| Milestone | Expected output | Target date | Responsible |
|---|---|---|---|
| Proposal | Project concept and approved target | 11-12-2026 | All members |
| System Design | Architecture, database, workflow | 11-18-2026 | Project lead, backend, frontend |
| Initial Development | Working frontend, backend, database | 11-22-2026 | Frontend and backend developers |
| Security Integration | Reconnaissance, scanning, assessment features | **11-28-2026** | Backend developer and security tester |
| AI Integration | At least two working AI functionalities | 12-02-2026 | AI integration developer |
| Finalization | Verification, dashboard, report generation | 12-10-2026 | All members |
| Final Presentation | Deployed system and complete documentation | 12-15-2026 | All members |

**As of 2026-11-23:** the Initial Development date has just passed, and Security Integration is due in 5 days. About 3 weeks remain until the final presentation. Prioritize the end-to-end path (scope → scan → findings → AI → verify → report) over breadth. Update status here as milestones close.

---

## 16. Glossary

- **Assessment:** one end-to-end security evaluation of one target.
- **Finding:** a potential vulnerability or weakness, normalized from tool output or added manually.
- **Evidence:** raw output, request/response snippet, screenshot, or note supporting a finding.
- **Verification:** the assessor's decision (Confirmed / False Positive / Needs Retest).
- **False positive:** a reported issue that is not a real vulnerability.
- **Scope guard:** backend component that allows, blocks, rate-limits, and audits every tool run and target request.
- **Redaction / sanitizer:** component that strips secrets and personal data before text goes to an AI.
- **IDOR:** insecure direct object reference, e.g. reading another record by changing an ID in the URL.

---

## 17. Decisions and open questions

**Decided (from the signed proposal and team answers)**
- Name: **PenPal**. Target: **Love & Styles Rental System**, local, synthetic data.
- Stack: React, Python/FastAPI, PostgreSQL, Docker Compose.
- Tools: Nmap, dig, whois, WhatWeb, OWASP ZAP (daemon), Python `http_checks` (httpx).
- AI: Gemini free tier primary, OpenRouter free-tier fallback (failover only); three functions (interpret, remediate, summary); redaction before sending; all AI traffic audited.
- Roles: LSRS has only admin and staff. There is no customer role.
- Verification states: Confirmed / False Positive / Needs Retest. Only Confirmed counts as a vulnerability and goes in the main report; false positives are excluded from severity counts; pending/needs-retest AI suggestions go in an appendix, labelled unverified.
- Severity matrix: likelihood 1–5 × impact 1–5. Bands: 20–25 critical, 12–19 high, 6–11 medium, 3–5 low, 1–2 informational. The server computes final severity.
- Remediation timing: AI remediation is a pre-verification suggestion; confirmation may accept it as-is with an audit entry, and a confirmed finding may re-run remediation with verified context.
- Assessment summaries are drafts until approved; only the approved summary is used in the report, with unapproved drafts confined to the AI appendix.
- Where tools run: one backend image with Nmap/dig/whois/WhatWeb installed; HTTP checks run in-process with httpx behind the scope guard.
- Methodology: WSTG + NIST SP 800-115 + PTES; OWASP Top 10 + CWE mapping.

**⚠ OPEN questions for the team**
- [ ] **Exact LSRS address/port:** set `LSRS_BASE_URL`; do not guess. Prefer an LSRS Compose service over exposing a host port.
- [ ] **Final Gemini and OpenRouter model names:** set via environment variables; free models may change or disappear.
- [ ] **Authorization record:** confirm the instructor's acknowledgment is on file with the authorization letter.
- [ ] **Demo hosting:** local machine or Linux VM.
- [x] **Deployed LSRS URL:** team states the deployed LSRS is authorized. Use the exact host in `ALLOWED_PUBLIC_TARGETS` with `ALLOW_PUBLIC_TARGETS=true`; keep written authorization on file. Every other public target stays blocked.

---

## 18. Conventions for contributors and coding agents

- Keep scope tight. Build what this document and the task prompt ask for. Propose additions instead of adding them.
- Record non-obvious decisions in `docs/DECISIONS.md` and progress in `docs/PROGRESS.md`.
- Never commit secrets. Use `.env` (git-ignored) and keep `.env.example` current.
- Tests must **not** make real network calls to scan targets, ZAP, or AI services. Use fixtures and fakes.
- Python: type hints everywhere, `ruff` for lint/format, small modules, no business logic in route handlers (put it in `services/`).
- Any change touching scope enforcement, redaction, or verification rules needs tests.
- Use the terminology in §13 (`false_positive`, not `rejected`) consistently in code, API, UI, and reports.

---

## 19. Change log

- **v0.3 (2026-11-24):** Synced to team decisions: admin/staff only (no customer role), decided L×I bands with server-computed severity, Gemini→OpenRouter failover chain, approved summary workflow, HTTP checks via httpx, tools in one backend image. Public targets remain blocked; exact LSRS address and model names stay open.
- **v0.2 (2026-11-23):** Updated from the signed proposal. Target details and authorization, five assessment categories, added DNS tools/WhatWeb/curl, three AI functions (added summary generation), `false_positive` replaces `rejected`, likelihood × impact severity, PTES, real timeline dates, audit-trail scope (scope events and AI traffic), host-networking note, and a list of proposal inconsistencies.
- **v0.1 (2026-11-23):** Initial draft from the blank proposal template.