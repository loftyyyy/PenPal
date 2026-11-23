from __future__ import annotations

import pytest
from app.services.sanitizer import sanitize_data, sanitize_text


def _clean(value: str, *, max_chars: int | None = None) -> str:
    return sanitize_text(value, max_chars=max_chars).text


def test_header_values_are_replaced_but_names_kept() -> None:
    raw = (
        "GET /account HTTP/1.1\r\n"
        "Host: 127.0.0.1:3000\r\n"
        "Cookie: sessionid=super-secret-cookie; theme=dark\r\n"
        "Set-Cookie: token=abc123; HttpOnly\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature\r\n"
        "X-API-Key: key_live_1234567890\r\n"
        "\r\n"
    )
    result = sanitize_text(raw)
    assert "super-secret-cookie" not in result.text
    assert "abc123" not in result.text
    assert "eyJhbGciOiJIUzI1NiJ9" not in result.text
    assert "key_live_1234567890" not in result.text
    assert "Cookie: [REDACTED_COOKIE]" in result.text
    assert "Set-Cookie: [REDACTED_COOKIE]" in result.text
    assert "Authorization: [REDACTED_AUTHORIZATION]" in result.text
    assert "X-API-Key: [REDACTED_API_KEY]" in result.text
    assert result.report["cookie_header"] == 2
    assert result.report["authorization_header"] == 1
    assert result.report["api_key_header"] == 1


def test_userinfo_and_absolute_url_hosts_are_redacted() -> None:
    result = sanitize_text(
        "See http://admin:hunter2@example.test:8080/admin?token=abc#x"
    )
    assert "admin:hunter2" not in result.text
    assert "hunter2" not in result.text
    assert "example.test" not in result.text
    assert result.text == "See http://[REDACTED_USERINFO]@[REDACTED_HOST]/admin?token=[REDACTED]#x"
    assert result.report["url_userinfo"] == 1
    assert result.report["url_host"] == 1
    assert result.report["query_value"] == 1


def test_query_names_survive_values_do_not() -> None:
    result = sanitize_text(
        "https://app.test/search?q=needle&page=2&password=hunter2&empty="
    )
    assert "needle" not in result.text
    assert "hunter2" not in result.text
    assert "page=" in result.text
    assert "password=" in result.text
    assert "q=[REDACTED]" in result.text
    assert result.report["query_value"] == 3


def test_sensitive_parameter_values_use_typed_placeholders() -> None:
    raw = (
        '{"username": "alice", "password": "hunter2", '
        '"api_key": "sk_live_abcdefghijklmnop", "session": "abc123", '
        '"csrf_token": "csrf-value", "auth": "basic-value"}'
    )
    result = sanitize_text(raw)
    assert "hunter2" not in result.text
    assert "sk_live_abcdefghijklmnop" not in result.text
    assert "abc123" not in result.text
    assert "csrf-value" not in result.text
    assert "basic-value" not in result.text
    assert '"password": "[REDACTED_PASSWORD]"' in result.text
    assert '"api_key": "[REDACTED_API_KEY]"' in result.text
    assert '"session": "[REDACTED_SESSION]"' in result.text
    assert '"csrf_token": "[REDACTED_CSRF]"' in result.text
    assert '"auth": "[REDACTED_AUTH]"' in result.text
    assert result.report["password"] == 1
    assert result.report["api_key"] == 1
    assert result.report["session"] == 1
    assert result.report["csrf"] == 1
    assert result.report["auth"] == 1


def test_jwt_bearer_and_provider_keys_are_redacted() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature-part"
    raw = (
        f"jwt={jwt}\n"
        "proxy says Bearer abcdefghijklmnopqrstuvwxyz\n"
        "aws=AKIAIOSFODNN7EXAMPLE\n"
        "github=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n"
        "google=AIzaSyD-abcdefghijklmnopqrstuvwxyz12345\n"
        "stripe=sk_live_abcdefghijklmnop1234\n"
    )
    result = sanitize_text(raw)
    assert jwt not in result.text
    assert "abcdefghijklmnopqrstuvwxyz" not in result.text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in result.text
    assert "AIzaSyD-abcdefghijklmnopqrstuvwxyz12345" not in result.text
    assert "sk_live_abcdefghijklmnop1234" not in result.text
    assert "[REDACTED_JWT]" in result.text
    assert "[REDACTED_TOKEN]" in result.text
    assert result.report["jwt"] >= 1
    assert result.report["bearer_token"] >= 1
    assert result.report["api_key"] >= 4


def test_private_keys_and_long_hex_and_base64_are_redacted() -> None:
    raw = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA\n"
        "-----END RSA PRIVATE KEY-----\n"
        "sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "blob=QWxhZGRpbjpvcGVuIHNlc2FtZQ1234567890abcdefghij\n"
    )
    result = sanitize_text(raw)
    assert "MIIEowIBAAKCAQEA" not in result.text
    assert "0123456789abcdef" not in result.text
    assert "QWxhZGRpbjpvcGVu" not in result.text
    assert result.report["private_key"] == 1
    assert result.report["hex_secret"] >= 1
    assert result.report["base64_secret"] == 1


def test_emails_phones_and_valid_cards_are_redacted() -> None:
    raw = (
        "Contact alice.analyst+security@example.test or +63 917 123 4567. "
        "Call (02) 8123 4567 or 0917-123-4567. "
        "Card 4111 1111 1111 1111 should not appear. "
        "Invalid 1234 5678 9012 3456 may remain."
    )
    result = sanitize_text(raw)
    assert "alice.analyst+security@example.test" not in result.text
    assert "+63 917 123 4567" not in result.text
    assert "(02) 8123 4567" not in result.text
    assert "0917-123-4567" not in result.text
    assert "4111 1111 1111 1111" not in result.text
    assert "1234 5678 9012 3456" in result.text
    assert result.report["email"] == 1
    assert result.report["phone"] == 3
    assert result.report["card"] == 1


def test_ipv4_and_ipv6_are_redacted() -> None:
    raw = "host 127.0.0.1:3000 and 10.2.3.4, v6 ::1 and 2001:db8::1, version 1.2.3"
    result = sanitize_text(raw)
    assert "127.0.0.1" not in result.text
    assert "10.2.3.4" not in result.text
    assert "2001:db8::1" not in result.text
    assert "::1" not in result.text
    assert "[REDACTED_IP]:3000" in result.text
    assert "version 1.2.3" in result.text
    assert result.report["ip"] == 4


def test_http_exchange_secrets_never_survive() -> None:
    exchange = (
        "REQUEST\n"
        "GET /rest/user/1?email=alice@example.test&token=abc123 HTTP/1.1\r\n"
        "Host: 10.0.0.5:3000\r\n"
        "Authorization: Bearer 0123456789abcdef0123456789abcdef\r\n"
        "Cookie: sessionid=session-secret-value\r\n"
        "\r\n"
        "RESPONSE\n"
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: sessionid=session-secret-value; HttpOnly\r\n"
        "\r\n"
        '{"password":"hunter2","phone":"0917 123 4567"}'
    )
    secret_strings = [
        "alice@example.test",
        "abc123",
        "10.0.0.5",
        "0123456789abcdef0123456789abcdef",
        "session-secret-value",
        "hunter2",
        "0917 123 4567",
    ]
    result = sanitize_text(exchange)
    for secret in secret_strings:
        assert secret not in result.text
    assert "GET /rest/user/1" in result.text
    assert "token=" in result.text
    assert "Set-Cookie: [REDACTED_COOKIE]" in result.text
    assert result.report["authorization_header"] == 1
    assert result.report["cookie_header"] == 2
    assert result.report["query_value"] == 2
    assert result.report["ip"] == 1
    assert result.report["password"] == 1
    assert result.report["phone"] == 1


@pytest.mark.parametrize(
    "text",
    [
        "plain text with no secrets",
        "Cookie: a=b\r\nAuthorization: Bearer abcdefghijkl\r\n",
        "email alice@example.test and host 127.0.0.1",
        "https://user:pass@example.test/path?q=secret",
        '{"password":"hunter2","token":"abc123"}',
    ],
)
def test_sanitizer_is_idempotent(text: str) -> None:
    first = sanitize_text(text)
    second = sanitize_text(first.text)
    assert second.text == first.text
    assert second.report == {}


def test_truncation_is_bounded_and_idempotent() -> None:
    text = "A" * 50 + " secret@example.test " + "B" * 50
    first = sanitize_text(text, max_chars=30)
    assert len(first.text) == 30 + len("\n[TRUNCATED]")
    assert first.text.endswith("[TRUNCATED]")
    assert "secret@example.test" not in first.text
    second = sanitize_text(first.text, max_chars=30)
    assert second.text == first.text


def test_sanitize_data_walks_nested_structures() -> None:
    payload, report = sanitize_data(
        {
            "url": "http://127.0.0.1:3000/search?q=needle",
            "headers": {"Cookie": "session=abc", "Accept": "text/html"},
            "items": ["alice@example.test", 42, None, {"ip": "10.0.0.5"}],
        }
    )
    assert payload["url"] == "http://[REDACTED_HOST]/search?q=[REDACTED]"
    assert payload["headers"]["Cookie"] == "[REDACTED_COOKIE]"
    assert payload["headers"]["Accept"] == "text/html"
    assert payload["items"][0] == "[REDACTED_EMAIL]"
    assert payload["items"][1] == 42
    assert payload["items"][2] is None
    assert payload["items"][3]["ip"] == "[REDACTED_IP]"
    assert report["url_host"] == 1
    assert report["cookie_header"] == 1
    assert report["email"] == 1
    assert report["ip"] == 1
