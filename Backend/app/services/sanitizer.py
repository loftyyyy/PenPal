"""Redact secrets and personal data before text goes to an AI provider.

Everything sent to a model passes through here. The sanitiser keeps parameter
and header *names* so a model can still reason about the issue, but replaces
values with stable placeholders. It is deterministic, idempotent and reports
how many of each kind of value it redacted.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

REDACTED = "[REDACTED]"
TRUNCATION_MARKER = "\n[TRUNCATED]"


@dataclass(frozen=True)
class SanitizationResult:
    text: str
    report: dict[str, int]


class _Counter:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def hit(self, kind: str, amount: int = 1) -> None:
        if amount:
            self.counts[kind] = self.counts.get(kind, 0) + amount


_HEADER_NAMES = {
    "cookie": "cookie",
    "set-cookie": "cookie",
    "authorization": "authorization",
    "proxy-authorization": "authorization",
    "x-api-key": "api_key",
    "api-key": "api_key",
    "apikey": "api_key",
    "x-auth-token": "token",
    "x-access-token": "token",
    "x-amz-security-token": "token",
    "x-session-token": "session",
    "x-csrf-token": "csrf",
    "x-client-secret": "secret",
}

_HEADER_RE = re.compile(
    r"(?im)^([ \t]*(?P<name>"
    + "|".join(re.escape(name) for name in _HEADER_NAMES)
    + r")[ \t]*:)(?>[ \t]*)(?!\[REDACTED)([^\r\n]*)"
)

_USERINFO_RE = re.compile(r"(?i)\b(https?://)(?!\[REDACTED)([^/@\s]+)@")
_URL_HOST_RE = re.compile(
    r"(?i)\b(https?://)(?:(?P<userinfo>[^/\s\"'<>@]+)@)?"
    r"(?!\[REDACTED)([^/\s\"'<>@]+)"
)

_QUERY_RE = re.compile(r"([?&;])([^=\s&#;\"'<>]+)=([^&#\s\"'<>]*)")

_PARAM_RE = re.compile(
    r"(?i)([\"']?(?P<key>"
    r"password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"session(?:[_-]?id)?|csrf(?:[_-]?token)?|auth(?:orization)?"
    r")[\"']?\s*[:=]\s*[\"']?)(?!\[REDACTED)([^\"'\s,&}]+)"
)

_PARAM_KINDS = (
    ("password", "password"),
    ("passwd", "password"),
    ("pwd", "password"),
    ("token", "token"),
    ("secret", "secret"),
    ("api_key", "api_key"),
    ("session", "session"),
    ("csrf", "csrf"),
    ("auth", "auth"),
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_BEARER_RE = re.compile(r"(?i)\b(Bearer\s+)(?!\[REDACTED)[A-Za-z0-9._~+/=-]{8,}")
_BASIC_RE = re.compile(r"(?i)\b(Basic\s+)(?!\[REDACTED)[A-Za-z0-9+/=]{8,}")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_API_KEY_RES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "github"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "google"),
    (re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "stripe"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack"),
)
_HEX_SECRET_RE = re.compile(
    r"\b(?=[A-Fa-f0-9]*[0-9])(?=[A-Fa-f0-9]*[A-Fa-f])[A-Fa-f0-9]{32,}\b"
)
_BASE64_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RES = (
    re.compile(r"(?<![\d+])\+\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?![\d])"),
    re.compile(r"(?<![\d(])\(\d{2,4}\)[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?![\d])"),
    re.compile(r"(?<![\d])\d{3}[\s.-]\d{3}[\s.-]\d{4}(?![\d])"),
    re.compile(r"(?<![\d])\d{4}[\s.-]\d{3}[\s.-]\d{4}(?![\d])"),
)
_CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){13,19}(?![\d-])")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])(?=[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{3,}(?![\w:])")


def _placeholder(kind: str) -> str:
    return f"[REDACTED_{kind.upper()}]"


def _param_kind(key: str) -> str:
    normalized = key.lower().replace("-", "_")
    for prefix, kind in _PARAM_KINDS:
        if normalized == prefix or normalized.startswith(prefix + "_"):
            return kind
    return "value"


def _luhn(number: str) -> bool:
    digits = [int(character) for character in number if character.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _looks_like_base64_secret(value: str) -> bool:
    if len(value) < 40:
        return False
    has_upper = any(character.isupper() for character in value)
    has_lower = any(character.islower() for character in value)
    has_digit = any(character.isdigit() for character in value)
    return has_upper and has_lower and has_digit


def _replace_ipv4(text: str, counter: _Counter) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        counter.hit("ip")
        return _placeholder("IP")

    return _IPV4_RE.sub(replace, text)


def _replace_ipv6(text: str, counter: _Counter) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if candidate.count(":") < 2:
            return candidate
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        if address.version != 6:
            return candidate
        counter.hit("ip")
        return _placeholder("IP")

    return _IPV6_CANDIDATE_RE.sub(replace, text)


def _replace_cards(text: str, counter: _Counter) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if not _luhn(candidate):
            return candidate
        counter.hit("card")
        return _placeholder("CARD")

    return _CARD_RE.sub(replace, text)


def sanitize_text(value: str | None, *, max_chars: int | None = None) -> SanitizationResult:
    """Return redacted text and per-type counts. Safe to call twice."""
    counter = _Counter()
    text = value or ""

    # URL structure first: userinfo and hostnames are not needed for triage.
    text, removed = _USERINFO_RE.subn(
        lambda match: match.group(1) + _placeholder("USERINFO") + "@", text
    )
    counter.hit("url_userinfo", removed)

    def redact_url_host(match: re.Match[str]) -> str:
        counter.hit("url_host")
        userinfo = match.group("userinfo")
        prefix = f"{userinfo}@" if userinfo else ""
        return f"{match.group(1)}{prefix}{_placeholder('HOST')}"

    text = _URL_HOST_RE.sub(redact_url_host, text)

    # Header values are the most reliable secret carrier.
    def redact_header(match: re.Match[str]) -> str:
        kind = _HEADER_NAMES[match.group("name").lower()]
        counter.hit(f"{kind}_header")
        return f"{match.group(1)} {_placeholder(kind)}"

    text = _HEADER_RE.sub(redact_header, text)

    # Query values are dropped while their names are kept.
    def redact_query(match: re.Match[str]) -> str:
        value_part = match.group(3)
        if not value_part or value_part.startswith("[REDACTED"):
            return match.group(0)
        counter.hit("query_value")
        return f"{match.group(1)}{match.group(2)}={REDACTED}"

    text = _QUERY_RE.sub(redact_query, text)

    def redact_param(match: re.Match[str]) -> str:
        kind = _param_kind(match.group("key"))
        counter.hit(kind)
        return match.group(1) + _placeholder(kind)

    text = _PARAM_RE.sub(redact_param, text)

    text, removed = _PRIVATE_KEY_RE.subn(_placeholder("PRIVATE_KEY"), text)
    counter.hit("private_key", removed)
    text, removed = _JWT_RE.subn(_placeholder("JWT"), text)
    counter.hit("jwt", removed)
    text, removed = _BEARER_RE.subn(
        lambda match: match.group(1) + _placeholder("TOKEN"), text
    )
    counter.hit("bearer_token", removed)
    text, removed = _BASIC_RE.subn(
        lambda match: match.group(1) + _placeholder("AUTH"), text
    )
    counter.hit("basic_auth", removed)
    for pattern, _name in _API_KEY_RES:
        text, removed = pattern.subn(_placeholder("API_KEY"), text)
        counter.hit("api_key", removed)
    text, removed = _HEX_SECRET_RE.subn(_placeholder("HEX"), text)
    counter.hit("hex_secret", removed)

    def redact_base64(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if not _looks_like_base64_secret(candidate):
            return candidate
        counter.hit("base64_secret")
        return _placeholder("BASE64")

    text = _BASE64_SECRET_RE.sub(redact_base64, text)

    text, removed = _EMAIL_RE.subn(_placeholder("EMAIL"), text)
    counter.hit("email", removed)

    def redact_phone(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if not 8 <= len(digits) <= 15:
            return match.group(0)
        counter.hit("phone")
        return _placeholder("PHONE")

    for pattern in _PHONE_RES:
        text = pattern.sub(redact_phone, text)

    text = _replace_cards(text, counter)
    text = _replace_ipv4(text, counter)
    text = _replace_ipv6(text, counter)

    if max_chars is not None and max_chars >= 0 and len(text) > max_chars:
        text = text[:max_chars] + TRUNCATION_MARKER
        counter.hit("truncated")

    return SanitizationResult(text=text, report=dict(sorted(counter.counts.items())))


def sanitize_data(value: Any, *, max_chars: int | None = None) -> tuple[Any, dict[str, int]]:
    """Recursively sanitise every string in a JSON-like structure.

    Dictionary keys that name a sensitive header or parameter protect their
    value even when the value alone has no recognisable secret shape.
    """
    report: dict[str, int] = {}

    def bump(kind: str) -> None:
        report[kind] = report.get(kind, 0) + 1

    def merge(counts: dict[str, int]) -> None:
        for kind, amount in counts.items():
            report[kind] = report.get(kind, 0) + amount

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            result = sanitize_text(item, max_chars=max_chars)
            merge(result.report)
            return result.text
        if isinstance(item, dict):
            result: dict[str, Any] = {}
            for key, child in item.items():
                name = str(key).strip()
                header_kind = _HEADER_NAMES.get(name.lower())
                if header_kind is not None:
                    bump(f"{header_kind}_header")
                    result[name] = _placeholder(header_kind)
                    continue
                param_kind = _param_kind(name)
                if param_kind != "value":
                    bump(param_kind)
                    result[name] = _placeholder(param_kind)
                    continue
                result[name] = walk(child)
            return result
        if isinstance(item, list | tuple):
            return [walk(child) for child in item]
        return item

    return walk(value), dict(sorted(report.items()))
