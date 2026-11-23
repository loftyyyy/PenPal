"""Table-driven tests for the scope guard. No network: resolver is injected."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from app.core.config import Settings
from app.db.enums import AssessmentStatus, ScanTool, ScopeKind
from app.db.models import Assessment, ScopeItem
from app.services.scope_guard import ScopeGuard, normalize_scope_value, normalize_target


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "env": "test",
        "secret_key": "s" * 40,
        "first_admin_password": "p" * 20,
        "zap_api_key": "z" * 20,
        "allowed_target_networks": (
            "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
        ),
        "allow_public_targets": False,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


class FakeResolver:
    def __init__(self, mapping: dict[str, list[str]]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    async def __call__(self, host: str) -> Sequence[str]:
        self.calls.append(host)
        try:
            return self.mapping[host]
        except KeyError as exc:
            raise OSError("no such host") from exc


def rule(kind: ScopeKind, value: str, in_scope: bool = True) -> ScopeItem:
    return ScopeItem(kind=kind, value=value, in_scope=in_scope)


def assessment(
    *,
    confirmed: bool = True,
    status: AssessmentStatus = AssessmentStatus.READY,
) -> Assessment:
    return Assessment(
        authorization_confirmed=confirmed,
        status=status,
        authorization_reference="signed letter",
    )


def resolver_for(**mapping: str) -> FakeResolver:
    return FakeResolver({host: ips.split(",") for host, ips in mapping.items()})


DEFAULT_DNS = {
    "lsrs.test": ["127.0.0.1"],
    "app.lsrs.test": ["127.0.0.1"],
    "mixed.test": ["10.0.0.5", "8.8.8.8"],
    "outonly.test": ["192.168.1.5"],
    "internal.test": ["192.168.1.5", "192.168.2.5"],
    "remote.test": ["203.0.113.9"],
}


async def run_guard(
    *,
    rules: list[ScopeItem],
    target: str,
    tool: ScanTool = ScanTool.ZAP,
    ports: list[int] | None = None,
    confirmed: bool = True,
    status: AssessmentStatus = AssessmentStatus.READY,
    settings: Settings | None = None,
    dns: dict[str, list[str]] | None = None,
):
    guard = ScopeGuard(settings or make_settings(), FakeResolver(dns or DEFAULT_DNS))
    return await guard.check(
        assessment(confirmed=confirmed, status=status), rules, target, tool, ports
    )


@pytest.mark.parametrize(
    ("target", "rules", "expected", "reason_fragment"),
    [
        (
            "http://lsrs.test:8080/admin",
            [rule(ScopeKind.HOST, "lsrs.test")],
            True,
            "authorized",
        ),
        (
            "http://LSRS.TEST./",
            [rule(ScopeKind.HOST, "lsrs.test")],
            True,
            "authorized",
        ),
        (
            "http://app.lsrs.test/",
            [rule(ScopeKind.HOST, "lsrs.test")],
            False,
            "default deny",
        ),
        (
            "http://app.lsrs.test/",
            [rule(ScopeKind.HOST, "*.lsrs.test")],
            True,
            "authorized",
        ),
        (
            "http://lsrs.test:8080/admin",
            [rule(ScopeKind.URL_PREFIX, "http://lsrs.test:8080/admin")],
            True,
            "authorized",
        ),
        (
            "http://lsrs.test:8080/admin/users",
            [rule(ScopeKind.URL_PREFIX, "http://lsrs.test:8080/admin")],
            True,
            "authorized",
        ),
        (
            "http://lsrs.test:8080/administrator",
            [rule(ScopeKind.URL_PREFIX, "http://lsrs.test:8080/admin")],
            False,
            "default deny",
        ),
        (
            "http://lsrs.test:8080/admin/users",
            [
                rule(ScopeKind.HOST, "lsrs.test"),
                rule(ScopeKind.URL_PREFIX, "http://lsrs.test:8080/admin", in_scope=False),
            ],
            False,
            "out-of-scope",
        ),
        (
            "https://lsrs.test:8080/admin",
            [rule(ScopeKind.URL_PREFIX, "http://lsrs.test:8080/admin")],
            False,
            "default deny",
        ),
        (
            "http://lsrs.test/admin",
            [rule(ScopeKind.URL_PREFIX, "http://lsrs.test:8080/admin")],
            False,
            "default deny",
        ),
        (
            "http://lsrs.test@evil.test/",
            [rule(ScopeKind.HOST, "evil.test")],
            False,
            "userinfo",
        ),
        (
            "http://2130706433/",
            [rule(ScopeKind.IP, "127.0.0.1")],
            False,
            "ambiguous",
        ),
        (
            "http://0x7f000001/",
            [rule(ScopeKind.IP, "127.0.0.1")],
            False,
            "hex or octal",
        ),
        (
            "http://0177.0.0.1/",
            [rule(ScopeKind.IP, "127.0.0.1")],
            False,
            "non-canonical",
        ),
        (
            "http://127.1/",
            [rule(ScopeKind.IP, "127.0.0.1")],
            False,
            "non-canonical",
        ),
        (
            "http://lsrs.test:8080/%61dmin",
            [rule(ScopeKind.URL_PREFIX, "http://lsrs.test:8080/admin")],
            True,
            "authorized",
        ),
        (
            "http://lsrs.test:8080/admin/../secret",
            [rule(ScopeKind.HOST, "lsrs.test")],
            False,
            "dot segments",
        ),
        (
            "http://lsrs.test:8080/admin",
            [],
            False,
            "default deny",
        ),
        (
            "http://lsrs.test:8080/admin",
            [rule(ScopeKind.HOST, "*.other.test")],
            False,
            "default deny",
        ),
        (
            "http://lsrs.test:8080/admin",
            [
                rule(ScopeKind.HOST, "lsrs.test"),
                rule(ScopeKind.HOST, "lsrs.test", in_scope=False),
            ],
            False,
            "out-of-scope",
        ),
        (
            "http://8.8.8.8/",
            [rule(ScopeKind.IP, "8.8.8.8")],
            False,
            "ALLOWED_TARGET_NETWORKS",
        ),
        (
            "http://remote.test/",
            [rule(ScopeKind.HOST, "remote.test")],
            False,
            "ALLOWED_TARGET_NETWORKS",
        ),
        (
            "http://mixed.test/",
            [rule(ScopeKind.HOST, "mixed.test")],
            False,
            "ALLOWED_TARGET_NETWORKS",
        ),
        (
            "http://lsrs.test/",
            [rule(ScopeKind.HOST, "lsrs.test")],
            True,
            "authorized",
        ),
        (
            "https://[::1]:8443/",
            [rule(ScopeKind.IP, "::1")],
            True,
            "authorized",
        ),
        (
            "http://[2606:4700:4700::1111]/",
            [rule(ScopeKind.IP, "2606:4700:4700::1111")],
            False,
            "ALLOWED_TARGET_NETWORKS",
        ),
        (
            "http://[::ffff:127.0.0.1]/",
            [rule(ScopeKind.IP, "127.0.0.1")],
            True,
            "authorized",
        ),
        (
            "http://lsrs.test/",
            [rule(ScopeKind.CIDR, "10.0.0.0/8")],
            False,
            "default deny",
        ),
        (
            "http://outonly.test/",
            [rule(ScopeKind.CIDR, "192.168.0.0/16")],
            True,
            "authorized",
        ),
        (
            "http://internal.test/",
            [rule(ScopeKind.CIDR, "192.168.1.0/24")],
            False,
            "not every resolved address",
        ),
        (
            "http://unknown.test/",
            [rule(ScopeKind.HOST, "unknown.test")],
            False,
            "DNS resolution failed",
        ),
    ],
)
async def test_scope_table(target, rules, expected, reason_fragment) -> None:
    decision = await run_guard(rules=rules, target=target)
    assert decision.allowed is expected, decision.reasons
    assert any(reason_fragment in reason for reason in decision.reasons), decision.reasons


async def test_unconfirmed_authorization_denies() -> None:
    decision = await run_guard(
        rules=[rule(ScopeKind.HOST, "lsrs.test")],
        target="http://lsrs.test/",
        confirmed=False,
    )
    assert not decision.allowed
    assert "authorization has not been confirmed" in decision.reasons[0]


async def test_archived_assessment_denies() -> None:
    decision = await run_guard(
        rules=[rule(ScopeKind.HOST, "lsrs.test")],
        target="http://lsrs.test/",
        status=AssessmentStatus.ARCHIVED,
    )
    assert not decision.allowed
    assert "archived" in decision.reasons[0]


async def test_nmap_ports_rules() -> None:
    rules = [rule(ScopeKind.HOST, "lsrs.test"), rule(ScopeKind.PORT, "443")]
    allowed = await run_guard(
        rules=rules, target="lsrs.test", tool=ScanTool.NMAP, ports=[443]
    )
    assert allowed.allowed, allowed.reasons
    denied = await run_guard(
        rules=rules, target="lsrs.test", tool=ScanTool.NMAP, ports=[80]
    )
    assert not denied.allowed
    assert "not covered" in " ".join(denied.reasons)


async def test_nmap_out_of_scope_port_blocked() -> None:
    rules = [
        rule(ScopeKind.HOST, "lsrs.test"),
        rule(ScopeKind.PORT, "22", in_scope=False),
    ]
    decision = await run_guard(
        rules=rules, target="lsrs.test", tool=ScanTool.NMAP, ports=[22, 443]
    )
    assert not decision.allowed
    assert "out-of-scope port" in " ".join(decision.reasons)


async def test_invalid_port_rejected() -> None:
    decision = await run_guard(
        rules=[rule(ScopeKind.HOST, "lsrs.test")],
        target="lsrs.test",
        tool=ScanTool.NMAP,
        ports=[0],
    )
    assert not decision.allowed
    assert "between 1 and 65535" in " ".join(decision.reasons)


async def test_dns_re_resolved_each_check() -> None:
    resolver = FakeResolver({"lsrs.test": ["127.0.0.1"]})
    guard = ScopeGuard(make_settings(), resolver)
    rules = [rule(ScopeKind.HOST, "lsrs.test")]
    first = await guard.check(
        assessment(), rules, "http://lsrs.test/", ScanTool.ZAP
    )
    assert first.allowed
    resolver.mapping["lsrs.test"] = ["8.8.8.8"]
    second = await guard.check(
        assessment(), rules, "http://lsrs.test/", ScanTool.ZAP
    )
    assert not second.allowed
    assert len(resolver.calls) == 2


async def test_zap_context_excludes_out_of_scope_prefix() -> None:
    rules = [
        rule(ScopeKind.HOST, "lsrs.test"),
        rule(ScopeKind.URL_PREFIX, "http://lsrs.test/logout", in_scope=False),
        rule(ScopeKind.HOST, "evil.test", in_scope=False),
    ]
    decision = await run_guard(
        rules=rules, target="http://lsrs.test/login", tool=ScanTool.ZAP
    )
    assert decision.allowed
    joined_include = "\n".join(decision.context_include)
    joined_exclude = "\n".join(decision.context_exclude)
    assert "lsrs" in joined_include
    assert "logout" in joined_exclude
    assert "evil" in joined_exclude


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        (ScopeKind.HOST, "LSRS.Test.", "lsrs.test"),
        (ScopeKind.HOST, "*.Lsrs.Test", "*.lsrs.test"),
        (ScopeKind.CIDR, "192.168.1.5/24", "192.168.1.0/24"),
        (ScopeKind.IP, "127.0.0.1", "127.0.0.1"),
        (ScopeKind.PORT, "0443", "443"),
        (ScopeKind.URL_PREFIX, "HTTP://LSRS.Test:8080/admin/", "http://lsrs.test:8080/admin"),
    ],
)
def test_scope_value_normalisation(kind, value, expected) -> None:
    assert normalize_scope_value(kind, value) == expected


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (ScopeKind.PORT, "0"),
        (ScopeKind.PORT, "65536"),
        (ScopeKind.PORT, "80-90"),
        (ScopeKind.IP, "not-an-ip"),
        (ScopeKind.CIDR, "0.0.0.0/0"),
        (ScopeKind.CIDR, "0::/0"),
        (ScopeKind.HOST, "http://example.test"),
        (ScopeKind.HOST, "foo.*.example.test"),
        (ScopeKind.URL_PREFIX, "ftp://example.test/admin"),
        (ScopeKind.URL_PREFIX, "http://user:pass@example.test/admin"),
        (ScopeKind.URL_PREFIX, "http://example.test/admin?x=1"),
    ],
)
def test_invalid_scope_values(kind, value) -> None:
    with pytest.raises(ValueError):
        normalize_scope_value(kind, value)


@pytest.mark.parametrize(
    "raw",
    [
        "http://example.test/#frag",
        "http://example.test:99999/",
        "ftp://example.test/",
        "http://example.test/a\\b",
        "http://example.test/a b",
        "http://example.test/%zz",
        "",
    ],
)
def test_invalid_targets(raw) -> None:
    with pytest.raises(ValueError):
        normalize_target(raw, ScanTool.ZAP)


def test_nmap_target_accepts_bare_host_and_port() -> None:
    target = normalize_target("lsrs.test:8080", ScanTool.NMAP)
    assert target.host == "lsrs.test"
    assert target.port == 8080


def test_public_targets_can_be_enabled_explicitly() -> None:
    # Covered as a policy switch only; this is never used in the course project.
    import asyncio

    settings = make_settings(allow_public_targets=True)
    guard = ScopeGuard(settings, FakeResolver({}))
    decision = asyncio.run(
        guard.check(
            assessment(),
            [rule(ScopeKind.IP, "8.8.8.8")],
            "http://8.8.8.8/",
            ScanTool.ZAP,
        )
    )
    assert decision.allowed
