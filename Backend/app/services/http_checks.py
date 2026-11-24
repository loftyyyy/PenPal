"""HTTP checks for authentication, session, access-control and configuration."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.errors import AppError, ConflictError, NotFoundError
from app.db.base import utcnow
from app.db.enums import (
    FindingCategory,
    ScanTool,
    Severity,
)
from app.db.models import (
    Assessment,
    HttpCheckConfig,
    Scan,
    ScopeItem,
    TestAccount,
    User,
)
from app.schemas.http_checks import (
    AccessRule,
    HttpCheckConfigIn,
    HttpCheckLimits,
    LoginSpec,
    TestAccountCreate,
)
from app.services import audit
from app.services.credentials import decrypt_secret, encrypt_secret
from app.services.nmap_runner import ScanCancelled
from app.services.sanitizer import redact_known_secrets, sanitize_text
from app.services.scope_guard import ScopeGuard


@dataclass(frozen=True)
class AccountSecret:
    account: TestAccount
    password: str


@dataclass
class HttpCheckRunResult:
    document: dict[str, Any]
    findings: list[dict[str, Any]]


class HttpCheckLimitReached(RuntimeError):
    pass


class HttpCheckError(RuntimeError):
    pass


async def get_config(
    db: AsyncSession, assessment_id: int
) -> HttpCheckConfig | None:
    return await db.scalar(
        select(HttpCheckConfig).where(
            HttpCheckConfig.assessment_id == assessment_id
        )
    )


async def upsert_config(
    db: AsyncSession,
    assessment: Assessment,
    payload: HttpCheckConfigIn,
    user: User,
) -> HttpCheckConfig:
    config = await get_config(db, assessment.id)
    if config is None:
        config = HttpCheckConfig(
            assessment_id=assessment.id,
            access_rules=[],
            roles=[],
            limits={},
        )
        db.add(config)
    config.login = payload.login.model_dump(mode="json") if payload.login else None
    config.access_rules = [
        rule.model_dump(mode="json") for rule in payload.access_rules
    ]
    config.roles = list(dict.fromkeys(payload.roles))
    config.limits = payload.limits.model_dump(mode="json")
    config.updated_by = user.id
    await db.flush()
    await audit.record(
        db,
        "http_checks.config_updated",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="assessment",
        entity_id=assessment.id,
        details={"roles": config.roles, "access_rules": len(config.access_rules)},
    )
    await db.commit()
    await db.refresh(config)
    return config


async def list_accounts(
    db: AsyncSession, assessment_id: int
) -> list[TestAccount]:
    return list(
        (
            await db.execute(
                select(TestAccount)
                .where(TestAccount.assessment_id == assessment_id)
                .order_by(TestAccount.role, TestAccount.username)
            )
        )
        .scalars()
        .all()
    )


async def create_account(
    db: AsyncSession,
    assessment: Assessment,
    payload: TestAccountCreate,
    user: User,
    settings: Settings,
) -> TestAccount:
    config = await get_config(db, assessment.id)
    allowed_roles = config.roles if config and config.roles else ["staff", "admin"]
    if payload.role not in allowed_roles:
        raise AppError(
            422,
            "invalid_test_account",
            "role must be one of the configured roles: "
            + ", ".join(allowed_roles),
        )
    existing = await db.scalar(
        select(TestAccount).where(
            TestAccount.assessment_id == assessment.id,
            TestAccount.role == payload.role,
            TestAccount.username == payload.username,
        )
    )
    if existing is not None:
        raise ConflictError("A test account with this role and username exists")
    account = TestAccount(
        assessment_id=assessment.id,
        role=payload.role,
        username=payload.username,
        password_encrypted=encrypt_secret(payload.password, settings),
        created_by=user.id,
    )
    db.add(account)
    await db.flush()
    await audit.record(
        db,
        "test_account.created",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="test_account",
        entity_id=account.id,
        details={"role": account.role},
    )
    await db.commit()
    await db.refresh(account)
    return account


async def delete_account(
    db: AsyncSession, assessment_id: int, account_id: int, user: User
) -> None:
    account = await db.scalar(
        select(TestAccount).where(
            TestAccount.id == account_id,
            TestAccount.assessment_id == assessment_id,
        )
    )
    if account is None:
        raise NotFoundError("Test account", account_id)
    await db.delete(account)
    await audit.record(
        db,
        "test_account.deleted",
        user_id=user.id,
        assessment_id=assessment_id,
        entity_type="test_account",
        entity_id=account_id,
    )
    await db.commit()


def _parse_specs(
    config: HttpCheckConfig | None,
) -> tuple[LoginSpec | None, list[AccessRule], HttpCheckLimits, list[str]]:
    if config is None:
        return None, [], HttpCheckLimits(), ["staff", "admin"]
    login = LoginSpec.model_validate(config.login) if config.login else None
    rules = [AccessRule.model_validate(item) for item in config.access_rules]
    limits = HttpCheckLimits.model_validate(config.limits or {})
    roles = config.roles or ["staff", "admin"]
    return login, rules, limits, roles


@dataclass
class _HttpSession:
    role: str
    cookies: dict[str, str]
    username: str


class HttpCheckRunner:
    def __init__(
        self,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.transport = transport

    async def run(
        self,
        *,
        scan: Scan,
        assessment: Assessment,
        rules: list[ScopeItem],
        user_id: int,
        confirm_lockout_test: bool,
        cancel_event: asyncio.Event,
        progress: Any,
    ) -> HttpCheckRunResult:
        async with self.session_factory() as db:
            config = await get_config(db, assessment.id)
            accounts = await list_accounts(db, assessment.id)
        login, access_rules, limits, roles = _parse_specs(config)
        account_secrets = [
            AccountSecret(
                account=account,
                password=decrypt_secret(
                    account.password_encrypted, self.settings
                ),
            )
            for account in accounts
        ]
        self._known_secrets = [secret.password for secret in account_secrets]
        self._rules = rules
        self._assessment = assessment
        self._user_id = user_id
        self._limits = limits
        self._login_spec = login
        self._findings: list[dict[str, Any]] = []
        self._notes: list[str] = []
        self._requests = 0
        self._logins = 0
        self._last_request = 0.0
        self._last_login = 0.0
        self._guard = ScopeGuard(self.settings)
        self._base = scan.target.rstrip("/") + "/"
        self._cancel_event = cancel_event
        self._profile = scan.profile
        profile = scan.profile
        started = utcnow()

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(min(15.0, max(3.0, float(self.settings.ai_timeout_seconds)))),
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            await progress(10)
            try:
                if profile == "config_baseline":
                    await self._config_baseline(client)
                elif profile == "session":
                    await self._session_checks(client, account_secrets)
                elif profile == "access_control":
                    await self._access_control(client, account_secrets, access_rules)
                elif profile == "auth_limited":
                    await self._auth_limited(
                        client, account_secrets, confirm_lockout_test
                    )
                else:
                    raise HttpCheckError(f"Unsupported HTTP check profile: {profile}")
            except HttpCheckLimitReached as exc:
                self._notes.append(str(exc))
            await progress(90)

        document = {
            "tool": "http_checks",
            "profile": profile,
            "target": scan.target,
            "started_at": started.isoformat(),
            "finished_at": utcnow().isoformat(),
            "requests": self._requests,
            "notes": self._notes,
            "findings": len(self._findings),
        }
        return HttpCheckRunResult(document=document, findings=self._findings)

    # ------------------------------------------------------------------ HTTP

    async def _audit_request(
        self, allowed: bool, reasons: list[str], url: str, method: str
    ) -> None:
        async with self.session_factory() as db:
            await audit.record(
                db,
                "http_check.request",
                user_id=self._user_id,
                assessment_id=self._assessment.id,
                entity_type="http_check",
                entity_id=None,
                details={
                    "method": method,
                    "path": urlsplit(url).path or "/",
                    "allowed": allowed,
                    "reasons": reasons,
                },
            )
            await db.commit()

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> httpx.Response | None:
        if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
            raise HttpCheckError("method is not allowed by PenPal")
        if self._requests >= self._limits.max_requests:
            raise HttpCheckLimitReached(
                f"request budget of {self._limits.max_requests} reached; remaining checks skipped"
            )
        if self._cancel_event.is_set():
            raise ScanCancelled("scan cancelled")
        url = path if "://" in path else urljoin(self._base, path.lstrip("/"))
        redirects = 0
        while True:
            decision = await self._guard.check(
                self._assessment,
                self._rules,
                url,
                ScanTool.HTTP_CHECKS,
                [],
            )
            await self._audit_request(
                decision.allowed, decision.reasons, url, method
            )
            if not decision.allowed:
                self._notes.append(
                    f"blocked out-of-scope request to {urlsplit(url).path or '/'}"
                )
                return None
            now = asyncio.get_running_loop().time()
            wait = max(0.0, self._last_request + 1 / self._limits.max_rps - now)
            if wait:
                await asyncio.sleep(wait)
            self._last_request = asyncio.get_running_loop().time()
            self._requests += 1
            request_headers = dict(headers or {})
            if cookies:
                request_headers["Cookie"] = "; ".join(
                    f"{key}={value}" for key, value in cookies.items()
                )
            response = await client.request(
                method,
                url,
                headers=request_headers,
                data=data,
                json=json_body,
            )
            self._remember_cookies(response)
            location = response.headers.get("location")
            if (
                response.status_code in {301, 302, 303, 307, 308}
                and location
                and redirects < self._limits.max_redirects
            ):
                url = urljoin(url, location)
                redirects += 1
                method = "GET" if response.status_code == 303 else method
                continue
            return response

    def _remember_cookies(self, response: httpx.Response) -> None:
        for value in response.cookies.values():
            if value and value not in self._known_secrets:
                self._known_secrets.append(value)

    # -------------------------------------------------------------- helpers

    def _success(self, response: httpx.Response) -> bool:
        if response.status_code >= 400:
            return False
        location = response.headers.get("location", "")
        return not any(word in location.lower() for word in ("login", "signin", "error"))

    def _evidence(
        self,
        method: str,
        url: str,
        response: httpx.Response | None,
        *,
        request_headers: dict[str, str] | None = None,
    ) -> str:
        path = urlsplit(url).path or "/"
        lines = [
            "REQUEST",
            f"{method} {path} HTTP/1.1",
            f"Host: {urlsplit(url).netloc}",
        ]
        for key, value in (request_headers or {}).items():
            if key.lower() in {"cookie", "authorization", "x-api-key"}:
                lines.append(f"{key}: [REDACTED]")
            else:
                lines.append(f"{key}: {value}")
        if response is not None:
            lines.extend(
                [
                    "",
                    "RESPONSE",
                    f"HTTP/1.1 {response.status_code}",
                ]
            )
            for key in (
                "content-type",
                "content-length",
                "location",
                "set-cookie",
                "server",
                "x-powered-by",
                "access-control-allow-origin",
            ):
                if key in response.headers:
                    value = response.headers[key]
                    if key in {"set-cookie", "server", "x-powered-by"}:
                        value = "[REDACTED]"
                    lines.append(f"{key}: {value}")
            body = response.text[:2000]
            if body:
                lines.extend(["", sanitize_text(body).text])
        lines.extend(
            [
                "",
                "CURL EQUIVALENT (secrets use placeholders)",
                f"curl -sS -i '{urlsplit(url).scheme}://{urlsplit(url).netloc}{path}'"
                + (
                    " \\\n  -H 'Origin: https://example.invalid'"
                    if any(
                        key.lower() == "origin"
                        for key in (request_headers or {})
                    )
                    else ""
                ),
            ]
        )
        raw = redact_known_secrets("\n".join(lines), self._known_secrets)
        return sanitize_text(raw, max_chars=self.settings.evidence_text_max_chars).text

    def _add(
        self,
        *,
        rule_id: str,
        title: str,
        description: str,
        category: FindingCategory,
        severity: Severity,
        url: str,
        method: str = "GET",
        parameter: str | None = None,
        cwe: str | None = None,
        owasp: str | None = None,
        response: httpx.Response | None = None,
        request_headers: dict[str, str] | None = None,
        raw: dict[str, Any] | None = None,
    ) -> None:
        self._findings.append(
            {
                "rule_id": rule_id,
                "title": title,
                "description": description,
                "category": category.value,
                "severity": severity.value,
                "affected_url": url,
                "method": method,
                "parameter": parameter,
                "cwe": cwe,
                "owasp_category": owasp,
                "confidence": "HTTP check",
                "raw": raw or {},
                "evidence": self._evidence(
                    method, url, response, request_headers=request_headers
                ),
            }
        )

    # ------------------------------------------------------------ profiles

    async def _config_baseline(self, client: httpx.AsyncClient) -> None:
        response = await self._request(client, "GET", "/")
        if response is None:
            return
        headers = {key.lower(): value for key, value in response.headers.items()}
        csp = headers.get("content-security-policy", "")
        if not csp:
            self._add(
                rule_id="http-config:missing-csp",
                title="Content-Security-Policy header is missing",
                description="The response did not set a Content-Security-Policy header.",
                category=FindingCategory.SECURITY_CONFIGURATION,
                severity=Severity.LOW,
                url=str(response.url),
                cwe="CWE-693",
            )
        if "x-frame-options" not in headers and "frame-ancestors" not in csp:
            self._add(
                rule_id="http-config:missing-frame-protection",
                title="Missing anti-clickjacking protection",
                description="No X-Frame-Options header or frame-ancestors directive.",
                category=FindingCategory.SECURITY_CONFIGURATION,
                severity=Severity.MEDIUM,
                url=str(response.url),
                cwe="CWE-1021",
            )
        for name, label, severity, cwe in (
            ("x-content-type-options", "X-Content-Type-Options", Severity.LOW, "CWE-693"),
            ("referrer-policy", "Referrer-Policy", Severity.LOW, "CWE-693"),
            ("permissions-policy", "Permissions-Policy", Severity.INFO, "CWE-693"),
        ):
            if name not in headers:
                self._add(
                    rule_id=f"http-config:missing-{name}",
                    title=f"{label} header is missing",
                    description=f"The response did not set {label}.",
                    category=FindingCategory.SECURITY_CONFIGURATION,
                    severity=severity,
                    url=str(response.url),
                    cwe=cwe,
                )
        if response.url.scheme == "https":
            if "strict-transport-security" not in headers:
                self._add(
                    rule_id="http-config:missing-hsts",
                    title="Strict-Transport-Security header is missing",
                    description="HTTPS responses should set HSTS.",
                    category=FindingCategory.SECURITY_CONFIGURATION,
                    severity=Severity.MEDIUM,
                    url=str(response.url),
                    cwe="CWE-319",
                )
        else:
            self._add(
                rule_id="http-config:https-not-enabled",
                title="HTTPS is not enabled on the checked URL",
                description="The target responded over plain HTTP.",
                category=FindingCategory.SECURITY_CONFIGURATION,
                severity=Severity.LOW,
                url=str(response.url),
                cwe="CWE-319",
            )
        for name in ("server", "x-powered-by"):
            if headers.get(name):
                self._add(
                    rule_id=f"http-config:{name}-banner",
                    title=f"{name} banner discloses version information",
                    description=(
                        f"The response exposes {name}: {headers[name]}."
                    ),
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.INFO,
                    url=str(response.url),
                    cwe="CWE-200",
                )
        cors = await self._request(
            client,
            "GET",
            "/",
            headers={"Origin": "https://example.invalid"},
        )
        if cors is not None:
            allow_origin = cors.headers.get("access-control-allow-origin", "")
            allow_credentials = (
                cors.headers.get("access-control-allow-credentials", "").lower()
                == "true"
            )
            if allow_origin == "*" and allow_credentials:
                self._add(
                    rule_id="http-config:cors-wildcard-credentials",
                    title="CORS allows a wildcard origin with credentials",
                    description="Access-Control-Allow-Origin: * with credentials is unsafe.",
                    category=FindingCategory.SECURITY_CONFIGURATION,
                    severity=Severity.HIGH,
                    url=str(cors.url),
                    cwe="CWE-942",
                )
            elif allow_origin == "https://example.invalid":
                self._add(
                    rule_id="http-config:cors-reflected-origin",
                    title="CORS reflects an arbitrary Origin",
                    description="The target reflected an untrusted Origin header.",
                    category=FindingCategory.SECURITY_CONFIGURATION,
                    severity=Severity.MEDIUM,
                    url=str(cors.url),
                    cwe="CWE-942",
                )
        missing = await self._request(
            client, "GET", "/penpal-nonexistent-check-404"
        )
        if missing is not None:
            body = missing.text.lower()
            if any(
                marker in body
                for marker in ("traceback", "stack trace", "debug mode", "exception in")
            ):
                self._add(
                    rule_id="http-config:debug-error-page",
                    title="Error page exposes debug or stack-trace details",
                    description="The 404 response contained debug/stack-trace markers.",
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.LOW,
                    url=str(missing.url),
                    cwe="CWE-209",
                )
        self._cookie_findings(response)

    def _cookie_findings(self, response: httpx.Response) -> None:
        cookie_headers = response.headers.get_list("set-cookie")
        for cookie in cookie_headers:
            lower = cookie.lower()
            name = cookie.split("=", 1)[0].strip()[:100]
            if "httponly" not in lower:
                self._add(
                    rule_id=f"http-session:httponly:{name}",
                    title="Session cookie is missing HttpOnly",
                    description="A cookie was set without the HttpOnly flag.",
                    category=FindingCategory.SESSION_MANAGEMENT,
                    severity=Severity.LOW,
                    url=str(response.url),
                    cwe="CWE-1004",
                    response=response,
                )
            if response.url.scheme == "https" and "secure" not in lower:
                self._add(
                    rule_id=f"http-session:secure:{name}",
                    title="Cookie is missing the Secure flag",
                    description="An HTTPS cookie was set without Secure.",
                    category=FindingCategory.SESSION_MANAGEMENT,
                    severity=Severity.LOW,
                    url=str(response.url),
                    cwe="CWE-614",
                    response=response,
                )
            if "samesite" not in lower:
                self._add(
                    rule_id=f"http-session:samesite:{name}",
                    title="Cookie is missing SameSite",
                    description="A cookie was set without a SameSite attribute.",
                    category=FindingCategory.SESSION_MANAGEMENT,
                    severity=Severity.INFO,
                    url=str(response.url),
                    cwe="CWE-1275",
                    response=response,
                )

    async def _login_post(
        self,
        client: httpx.AsyncClient,
        username: str,
        password: str,
    ) -> httpx.Response | None:
        if self._login_spec is None:
            return None
        if self._logins >= self._limits.max_login_attempts:
            raise HttpCheckLimitReached(
                f"login attempt cap of {self._limits.max_login_attempts} reached"
            )
        now = asyncio.get_running_loop().time()
        wait = max(
            0.0,
            self._last_login
            + self._limits.min_login_interval_seconds
            - now,
        )
        if wait:
            await asyncio.sleep(wait)
        self._last_login = asyncio.get_running_loop().time()
        self._logins += 1
        fields = {
            self._login_spec.username_field: username,
            self._login_spec.password_field: password,
        }
        return await self._request(
            client,
            "POST",
            self._login_spec.url,
            data=fields if self._login_spec.content_type == "form" else None,
            json_body=fields if self._login_spec.content_type == "json" else None,
        )

    async def _login(
        self,
        client: httpx.AsyncClient,
        account: AccountSecret,
    ) -> _HttpSession | None:
        if self._login_spec is None:
            self._notes.append("session checks skipped: login is not configured")
            return None
        response = await self._login_post(
            client, account.account.username, account.password
        )
        if response is None or not self._success(response):
            self._notes.append(
                f"login failed for role {account.account.role}; session checks skipped"
            )
            return None
        if self._login_spec.success_regex and not re.search(
            self._login_spec.success_regex, response.text
        ):
            self._notes.append(
                f"login response did not match success regex for role "
                f"{account.account.role}"
            )
            return None
        self._cookie_findings(response)
        cookies = dict(response.cookies)
        return _HttpSession(
            role=account.account.role,
            cookies=cookies,
            username=account.account.username,
        )

    async def _session_checks(
        self, client: httpx.AsyncClient, accounts: list[AccountSecret]
    ) -> None:
        if not accounts:
            self._notes.append("session checks skipped: no test accounts configured")
            return
        for account in accounts:
            session = await self._login(client, account)
            if session is None:
                continue
            if not session.cookies:
                self._notes.append(
                    f"login for role {session.role} set no cookies"
                )
            self._notes.append(
                "idle timeout and post-logout replay are manual checks; no logout URL is configured"
            )

    async def _access_control(
        self,
        client: httpx.AsyncClient,
        accounts: list[AccountSecret],
        access_rules: list[AccessRule],
    ) -> None:
        if not access_rules:
            self._notes.append("access-control checks skipped: no access rules configured")
            return
        sessions = []
        for account in accounts:
            session = await self._login(client, account)
            if session is not None:
                sessions.append(session)
        for rule in access_rules:
            unauth = await self._request(client, rule.method, rule.path)
            if (
                unauth is not None
                and self._success(unauth)
                and rule.allowed_roles
                and "anonymous" not in rule.allowed_roles
            ):
                self._add(
                    rule_id=f"http-access:unauth:{rule.method}:{rule.path}",
                    title="Unauthenticated access to a protected path",
                    description=(
                        f"{rule.method} {rule.path} succeeded without a session."
                    ),
                    category=FindingCategory.ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    url=str(unauth.url),
                    method=rule.method,
                    cwe="CWE-284",
                )
            for session in sessions:
                if session.role in rule.allowed_roles:
                    continue
                response = await self._request(
                    client,
                    rule.method,
                    rule.path,
                    cookies=session.cookies,
                )
                if response is not None and self._success(response):
                    self._add(
                        rule_id=(
                            f"http-access:role:{rule.method}:{rule.path}:{session.role}"
                        ),
                        title="Role can reach a path it should not access",
                        description=(
                            f"Role {session.role} received a success response for "
                            f"{rule.method} {rule.path}, which allows "
                            f"{', '.join(rule.allowed_roles) or 'no role'}."
                        ),
                        category=FindingCategory.ACCESS_CONTROL,
                        severity=Severity.HIGH,
                        url=str(response.url),
                        method=rule.method,
                        cwe="CWE-284",
                    )

    async def _auth_limited(
        self,
        client: httpx.AsyncClient,
        accounts: list[AccountSecret],
        confirm_lockout_test: bool,
    ) -> None:
        if self._login is None or not accounts:
            self._notes.append(
                "authentication checks skipped: login and a test account are required"
            )
            return
        account = accounts[0]
        invalid_user = await self._login_post(
            client, "penpal-invalid-user", "wrong-password"
        )
        valid_user = await self._login_post(
            client, account.account.username, "wrong-password"
        )
        if (
            invalid_user is not None
            and valid_user is not None
            and (
                invalid_user.status_code != valid_user.status_code
                or invalid_user.text.strip()[:200]
                != valid_user.text.strip()[:200]
            )
        ):
            self._add(
                    rule_id="http-auth:user-enumeration",
                    title="Login response differs for valid and invalid usernames",
                    description="Different status or message exposes username validity.",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.LOW,
                    url=str(valid_user.url),
                    method="POST",
                    cwe="CWE-204",
                )
        for weak in ("password", "admin", "admin123", "letmein", "123456"):
            if self._logins >= self._limits.max_login_attempts:
                self._notes.append("weak-credential checks stopped at login attempt cap")
                break
            await self._login_attempt(client, account, weak)
        if not confirm_lockout_test:
            self._notes.append(
                "lockout test skipped: resend with confirm_lockout_test=true to allow it"
            )

    async def _login_attempt(
        self, client: httpx.AsyncClient, account: AccountSecret, password: str
    ) -> None:
        if self._login_spec is None:
            return
        response = await self._login_post(
            client, account.account.username, password
        )
        if response is not None and self._success(response):
            self._add(
                rule_id=f"http-auth:weak-password:{account.account.role}",
                title="Configured test account accepts a weak password",
                description="A short fixed password list succeeded against a test account.",
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                url=str(response.url),
                method="POST",
                cwe="CWE-521",
            )
