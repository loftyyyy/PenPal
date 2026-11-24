"""Scope guard: the single authority for whether a target may be touched.

Design rules:
- Fail closed. Any parse ambiguity, DNS failure or malformed rule denies.
- Out-of-scope rules always beat in-scope rules.
- Every resolved IP must pass the network allowlist and the scope rules.
- The same function is called when a scan is requested and again when it runs.
- Pure and offline-testable: inject the DNS resolver.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from app.core.config import Settings
from app.db.enums import AssessmentStatus, ScanTool, ScopeKind
from app.db.models import Assessment, ScopeItem

Resolver = Callable[[str], Awaitable[Sequence[str]]]

MAX_TARGET_LENGTH = 2048
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_URL_SCHEMES = {"http", "https"}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class TargetError(ValueError):
    """The requested target is malformed or ambiguous."""


@dataclass(frozen=True)
class NormalizedTarget:
    original: str
    scheme: str | None
    host: str
    port: int | None
    path: str
    is_ip: bool
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    url: str | None = None

    @property
    def host_for_url(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host


@dataclass
class ScopeDecision:
    allowed: bool
    reasons: list[str]
    target: NormalizedTarget | None = None
    resolved_ips: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    context_include: list[str] = field(default_factory=list)
    context_exclude: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reasons": self.reasons,
            "target": None
            if self.target is None
            else {
                "host": self.target.host,
                "port": self.target.port,
                "path": self.target.path,
                "url": self.target.url,
            },
            "resolved_ips": self.resolved_ips,
            "matched_rules": self.matched_rules,
            "zap_context_include": self.context_include,
            "zap_context_exclude": self.context_exclude,
        }


def _deny(reasons: list[str], target: NormalizedTarget | None = None) -> ScopeDecision:
    return ScopeDecision(allowed=False, reasons=reasons, target=target)


def _canonical_ip(
    value: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _normalize_host(
    raw_host: str,
) -> tuple[str, bool, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    host = raw_host.strip()
    if not host:
        raise TargetError("target host is empty")
    if host.endswith("."):
        host = host.rstrip(".")
    if not host:
        raise TargetError("target host is empty")
    if "%" in host:
        raise TargetError("scoped IPv6 addresses must not contain a zone identifier")
    host = host.lower()

    # Reject ambiguous numeric encodings before any parser sees them. These are
    # classic scope-bypass tricks (decimal, octal and hex IPv4).
    labels = host.split(".")
    if re.fullmatch(r"[0-9]+", host):
        raise TargetError("numeric-only hosts are ambiguous and not accepted")
    if any(label.lower().startswith(("0x", "0o")) for label in labels):
        raise TargetError("hex or octal host encodings are not accepted")
    if all(re.fullmatch(r"[0-9]+", label) for label in labels) and (
        len(labels) != 4
        or any(len(label) > 1 and label.startswith("0") for label in labels)
    ):
        raise TargetError("non-canonical numeric IP encoding is not accepted")

    try:
        ip = _canonical_ip(host)
        return str(ip), True, ip
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetError("host is not a valid international domain name") from exc
    if len(ascii_host) > 253:
        raise TargetError("host is too long")
    for label in ascii_host.split("."):
        if not _HOST_LABEL.fullmatch(label):
            raise TargetError(f"invalid host label: {label!r}")
    return ascii_host, False, None


def _parse_host_port(value: str) -> tuple[str, int | None]:
    """Parse host[:port] or [v6][:port] without a scheme."""
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise TargetError("unterminated IPv6 bracket")
        host_part = value[1:end]
        rest = value[end + 1 :]
        if rest and not rest.startswith(":"):
            raise TargetError("invalid characters after IPv6 address")
        port_part = rest[1:] if rest.startswith(":") else ""
    elif value.count(":") > 1:
        # Bare IPv6 without a port.
        host_part, port_part = value, ""
    elif ":" in value:
        host_part, port_part = value.rsplit(":", 1)
    else:
        host_part, port_part = value, ""
    if port_part:
        if not re.fullmatch(r"[0-9]{1,5}", port_part):
            raise TargetError("port must be numeric")
        port = int(port_part)
        if not 1 <= port <= 65535:
            raise TargetError("port must be between 1 and 65535")
    else:
        port = None
    return host_part, port


def _clean_path(path: str) -> str:
    if not path:
        return "/"
    if _CONTROL_CHARS.search(path):
        raise TargetError("target path contains control characters")
    if re.search(r"%(?![0-9A-Fa-f]{2})", path):
        raise TargetError("target path has invalid percent encoding")
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeDecodeError as exc:
        raise TargetError("target path has invalid percent encoding") from exc
    if "\\" in decoded or _CONTROL_CHARS.search(decoded):
        raise TargetError("target path contains forbidden characters")
    segments = decoded.split("/")
    if any(segment in {"..", "."} for segment in segments):
        raise TargetError("target path must not contain dot segments")
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    return decoded


def normalize_target(raw: str, tool: ScanTool) -> NormalizedTarget:
    """Validate and canonicalise a scan target. Raises TargetError."""
    if not isinstance(raw, str):
        raise TargetError("target must be a string")
    text = raw.strip()
    if not text:
        raise TargetError("target is required")
    if len(text) > MAX_TARGET_LENGTH:
        raise TargetError("target is too long")
    if _CONTROL_CHARS.search(text) or any(ch.isspace() for ch in text):
        raise TargetError("target must not contain whitespace or control characters")
    if "\\" in text:
        raise TargetError("target must not contain backslashes")

    scheme: str | None = None
    port: int | None
    path = "/"
    url: str | None = None

    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text):
        if "@" in text.split("://", 1)[1].split("/", 1)[0]:
            raise TargetError("target URLs must not contain userinfo")
        try:
            parts = urlsplit(text)
            scheme = parts.scheme.lower()
            if scheme not in _URL_SCHEMES:
                raise TargetError("only http and https targets are supported")
            if parts.fragment:
                raise TargetError("target URLs must not contain a fragment")
            raw_host = parts.hostname or ""
            port = parts.port
        except ValueError as exc:
            raise TargetError(f"malformed target URL: {exc}") from exc
        if parts.username is not None or parts.password is not None:
            raise TargetError("target URLs must not contain userinfo")
        path = _clean_path(parts.path)
        if port is None:
            port = 443 if scheme == "https" else 80
        url = text
    else:
        if tool == ScanTool.ZAP:
            raise TargetError("ZAP targets must be absolute http(s) URLs")
        if any(marker in text for marker in ("/", "?", "#")):
            raise TargetError("host targets must not contain a path or query")
        raw_host, port = _parse_host_port(text)

    host, is_ip, ip = _normalize_host(raw_host)
    if is_ip and url is not None and ":" in host:
        # Rebuild a consistently bracketed IPv6 URL for display.
        url = None

    return NormalizedTarget(
        original=raw,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        is_ip=is_ip,
        ip=ip,
        url=url,
    )


def normalize_scope_value(kind: ScopeKind, value: str) -> str:
    """Canonicalise a scope item value. Raises TargetError when invalid."""
    raw = value.strip()
    if not raw:
        raise TargetError("scope value is required")
    if len(raw) > MAX_TARGET_LENGTH:
        raise TargetError("scope value is too long")

    if kind == ScopeKind.PORT:
        if not re.fullmatch(r"[0-9]{1,5}", raw):
            raise TargetError("port scope values must be integers")
        port = int(raw)
        if not 1 <= port <= 65535:
            raise TargetError("port must be between 1 and 65535")
        return str(port)

    if kind == ScopeKind.IP:
        try:
            return str(_canonical_ip(raw))
        except ValueError as exc:
            raise TargetError("invalid IP address") from exc

    if kind == ScopeKind.CIDR:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise TargetError("invalid CIDR network") from exc
        if isinstance(network, ipaddress.IPv6Network) and network.prefixlen == 0:
            raise TargetError("0::/0 is not an acceptable scope rule")
        if isinstance(network, ipaddress.IPv4Network) and network.prefixlen == 0:
            raise TargetError("0.0.0.0/0 is not an acceptable scope rule")
        return str(network)

    if kind == ScopeKind.HOST:
        if any(marker in raw for marker in ("/", "?", "#", "@")):
            raise TargetError("host scope values must not contain paths or userinfo")
        host = raw.lower()
        wildcard = host.startswith("*.")
        if wildcard:
            host = host[2:]
            if "*" in host:
                raise TargetError("only a leading wildcard is supported")
        if "*" in host:
            raise TargetError("only a leading wildcard is supported")
        canonical, _is_ip, _ip = _normalize_host(host)
        return f"*.{canonical}" if wildcard else canonical

    if kind == ScopeKind.URL_PREFIX:
        if "@" in raw.split("://", 1)[-1].split("/", 1)[0]:
            raise TargetError("URL prefixes must not contain userinfo")
        try:
            parts = urlsplit(raw)
            scheme = parts.scheme.lower()
            host = (parts.hostname or "").lower()
            port = parts.port
        except ValueError as exc:
            raise TargetError(f"invalid URL prefix: {exc}") from exc
        if scheme not in _URL_SCHEMES:
            raise TargetError("URL prefixes must start with http:// or https://")
        if not host:
            raise TargetError("URL prefix host is required")
        if parts.username is not None or parts.password is not None:
            raise TargetError("URL prefixes must not contain userinfo")
        if parts.query or parts.fragment:
            raise TargetError("URL prefixes must not contain a query or fragment")
        canonical_host, is_ip, _ = _normalize_host(host)
        path = _clean_path(parts.path).rstrip("/") or "/"
        port_part = f":{port}" if port is not None else ""
        host_part = f"[{canonical_host}]" if is_ip and ":" in canonical_host else canonical_host
        return f"{scheme}://{host_part}{port_part}{path}"

    raise TargetError(f"unsupported scope kind: {kind}")


async def default_resolver(host: str) -> list[str]:
    """Resolve every A/AAAA record through the system resolver."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    seen: set[str] = set()
    for info in infos:
        address = str(info[4][0])
        canonical = str(_canonical_ip(address))
        if canonical not in seen:
            seen.add(canonical)
            addresses.append(canonical)
    return addresses


def _host_rule_matches(rule_value: str, host: str) -> bool:
    rule = rule_value.lower()
    if rule.startswith("*."):
        suffix = rule[2:]
        return host.endswith("." + suffix) and host != suffix
    return host == rule


def _url_prefix_matches(
    prefix: str,
    target: NormalizedTarget,
) -> bool:
    parts = urlsplit(prefix)
    prefix_scheme = parts.scheme.lower()
    prefix_host = (parts.hostname or "").lower()
    prefix_port = parts.port or (443 if prefix_scheme == "https" else 80)
    prefix_path = _clean_path(parts.path).rstrip("/") or "/"

    if target.scheme != prefix_scheme:
        return False
    if target.host != prefix_host:
        return False
    if (target.port or (443 if target.scheme == "https" else 80)) != prefix_port:
        return False
    target_path = target.path.rstrip("/") or "/"
    if prefix_path == "/":
        return True
    return target_path == prefix_path or target_path.startswith(prefix_path + "/")


def _host_regex(
    host: str, *, wildcard: bool, port: int | None = None, path: str | None = None
) -> str:
    escaped = re.escape(host)
    if wildcard:
        host_part = rf"(?:[a-z0-9-]+\.)*{escaped}"
    elif ":" in host:
        host_part = rf"\[{escaped}\]"
    else:
        host_part = escaped
    port_part = f":{port}" if port is not None else r"(?::[0-9]{1,5})?"
    if path is None:
        return rf"^https?://{host_part}{port_part}(?:[/?#].*)?$"
    escaped_path = re.escape(path.rstrip("/") or "/")
    return rf"^https?://{host_part}{port_part}{escaped_path}(?:[/?#].*)?$"


def _scope_regexes(rules: Sequence[ScopeItem]) -> tuple[list[str], list[str]]:
    include: list[str] = []
    exclude: list[str] = []
    for rule in rules:
        bucket = include if rule.in_scope else exclude
        value = rule.value
        if rule.kind == ScopeKind.HOST:
            wildcard = value.startswith("*.")
            bucket.append(
                _host_regex(value[2:] if wildcard else value, wildcard=wildcard)
            )
        elif rule.kind == ScopeKind.IP:
            bucket.append(_host_regex(value, wildcard=False))
        elif rule.kind == ScopeKind.URL_PREFIX:
            parts = urlsplit(value)
            path = _clean_path(parts.path).rstrip("/") or "/"
            bucket.append(
                _host_regex(
                    (parts.hostname or "").lower(),
                    wildcard=False,
                    port=parts.port,
                    path=path,
                )
            )
        elif rule.kind == ScopeKind.PORT:
            if not rule.in_scope:
                exclude.append(rf"^https?://[^/]+:{re.escape(value)}/.*$")
    return sorted(set(include)), sorted(set(exclude))


class ScopeGuard:
    """Pure scope policy with an injectable resolver."""

    def __init__(
        self,
        settings: Settings,
        resolver: Resolver | None = None,
    ) -> None:
        self.settings = settings
        self.resolver: Resolver = resolver or default_resolver

    async def _resolve(self, target: NormalizedTarget) -> list[str]:
        if target.is_ip and target.ip is not None:
            return [str(target.ip)]
        try:
            raw_addresses = await self.resolver(target.host)
        except (OSError, ValueError) as exc:
            raise TargetError(f"DNS resolution failed for {target.host}") from exc
        addresses: list[str] = []
        seen: set[str] = set()
        for raw in raw_addresses:
            try:
                canonical = str(_canonical_ip(raw))
            except ValueError as exc:
                raise TargetError("DNS returned an invalid address") from exc
            if canonical not in seen:
                seen.add(canonical)
                addresses.append(canonical)
        if not addresses:
            raise TargetError(f"DNS resolution returned no addresses for {target.host}")
        return addresses

    def _network_allowed(
        self, addresses: Sequence[str], host: str | None = None
    ) -> list[str]:
        networks = self.settings.allowed_networks
        public_allowlist = set(self.settings.allowed_public_target_list)
        host_allowed = bool(host and host.rstrip(".").lower() in public_allowlist)
        denied: list[str] = []
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if any(ip in network for network in networks):
                continue
            if self.settings.allow_public_targets and host_allowed:
                continue
            denied.append(address)
        return denied

    async def check(
        self,
        assessment: Assessment,
        rules: Sequence[ScopeItem],
        raw_target: str,
        tool: ScanTool,
        requested_ports: Sequence[int] | None = None,
    ) -> ScopeDecision:
        reasons: list[str] = []
        if not assessment.authorization_confirmed:
            return _deny(["authorization has not been confirmed for this assessment"])
        if assessment.status == AssessmentStatus.ARCHIVED:
            return _deny(["assessment is archived"])

        try:
            target = normalize_target(raw_target, tool)
        except TargetError as exc:
            return _deny([str(exc)])

        try:
            resolved = await self._resolve(target)
        except TargetError as exc:
            return _deny([str(exc)], target)

        denied_ips = self._network_allowed(resolved, target.host)
        if denied_ips:
            reasons.append(
                "target resolves to addresses outside ALLOWED_TARGET_NETWORKS: "
                + ", ".join(denied_ips)
            )

        matched: list[str] = []
        out_hit = False

        for rule in rules:
            try:
                kind = ScopeKind(rule.kind)
            except ValueError:
                if rule.in_scope:
                    continue
                reasons.append(f"invalid out-of-scope rule {rule.id}")
                out_hit = True
                continue

            label = f"{kind.value}:{rule.value}"
            hit = False
            if kind == ScopeKind.HOST:
                hit = _host_rule_matches(rule.value, target.host)
            elif kind == ScopeKind.IP:
                hit = rule.value in resolved or (
                    target.is_ip and str(target.ip) == rule.value
                )
            elif kind == ScopeKind.CIDR:
                try:
                    network = ipaddress.ip_network(rule.value, strict=False)
                except ValueError:
                    if rule.in_scope:
                        continue
                    reasons.append(f"invalid out-of-scope rule {rule.id}")
                    out_hit = True
                    continue
                hit = any(ipaddress.ip_address(address) in network for address in resolved)
            elif kind == ScopeKind.URL_PREFIX:
                hit = _url_prefix_matches(rule.value, target)
            elif kind == ScopeKind.PORT:
                hit = target.port is not None and str(target.port) == rule.value

            if not hit:
                continue
            if rule.in_scope:
                matched.append(label)
            else:
                out_hit = True
                reasons.append(f"target matches out-of-scope rule {label}")

        in_scope_hits = list(matched)

        # For IP/CIDR-only scoping, *every* resolved address must be covered.
        host_rule_hit = any(
            rule.in_scope
            and rule.kind == ScopeKind.HOST
            and _host_rule_matches(rule.value, target.host)
            for rule in rules
        )
        url_rule_hit = any(
            rule.in_scope
            and rule.kind == ScopeKind.URL_PREFIX
            and _url_prefix_matches(rule.value, target)
            for rule in rules
        )
        if not host_rule_hit and not url_rule_hit and in_scope_hits:
            covered_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
            for rule in rules:
                if not rule.in_scope:
                    continue
                if rule.kind == ScopeKind.CIDR:
                    covered_networks.append(ipaddress.ip_network(rule.value, strict=False))
                elif rule.kind == ScopeKind.IP:
                    covered_networks.append(
                        ipaddress.ip_network(f"{rule.value}/32", strict=False)
                        if ipaddress.ip_address(rule.value).version == 4
                        else ipaddress.ip_network(f"{rule.value}/128", strict=False)
                    )
            uncovered = [
                address
                for address in resolved
                if not any(ipaddress.ip_address(address) in network for network in covered_networks)
            ]
            if uncovered:
                reasons.append(
                    "not every resolved address is covered by in-scope IP/CIDR rules: "
                    + ", ".join(uncovered)
                )

        if out_hit:
            reasons.insert(0, "out-of-scope rules override in-scope rules")

        if not in_scope_hits and not out_hit:
            reasons.append("target does not match any in-scope rule (default deny)")

        # Port rules for Nmap.
        if tool == ScanTool.NMAP and requested_ports:
            invalid = [port for port in requested_ports if not 1 <= int(port) <= 65535]
            if invalid:
                reasons.append("ports must be integers between 1 and 65535")
            port_rules_in = {
                int(rule.value) for rule in rules if rule.in_scope and rule.kind == ScopeKind.PORT
            }
            port_rules_out = {
                int(rule.value)
                for rule in rules
                if not rule.in_scope and rule.kind == ScopeKind.PORT
            }
            if port_rules_in:
                uncovered = [
                    int(port) for port in requested_ports if int(port) not in port_rules_in
                ]
                if uncovered:
                    reasons.append(
                        "requested ports are not covered by in-scope port rules: "
                        + ", ".join(str(port) for port in sorted(set(uncovered)))
                    )
            blocked = [
                int(port) for port in requested_ports if int(port) in port_rules_out
            ]
            if blocked:
                reasons.append(
                    "requested ports match out-of-scope port rules: "
                    + ", ".join(str(port) for port in sorted(set(blocked)))
                )

        allowed = not reasons and bool(in_scope_hits)
        decision = ScopeDecision(
            allowed=allowed,
            reasons=reasons if reasons else ["target is authorized and in scope"],
            target=target,
            resolved_ips=resolved,
            matched_rules=matched,
        )

        include, exclude = _scope_regexes(rules)
        # A CIDR-scoped target may have no host rule; include the queried host and
        # the IPs that actually passed the guard.
        if target.url is not None:
            target_regex = _host_regex(
                target.host,
                wildcard=False,
                port=None,
            )
            if not any(_host_rule_matches(_rule_host(item), target.host) for item in matched):
                include.append(target_regex)
        for address in resolved:
            exact_ip_rule = any(
                rule.in_scope and rule.kind == ScopeKind.IP and rule.value == address
                for rule in rules
            )
            if not exact_ip_rule:
                include.append(_host_regex(address, wildcard=False))
        decision.context_include = sorted(set(include))
        decision.context_exclude = exclude
        return decision


def _rule_host(label: str) -> str:
    """Extract the host from a matched rule label like 'host:example.test'."""
    value = label.split(":", 1)[-1]
    if value.startswith("*."):
        return value[2:]
    return value
