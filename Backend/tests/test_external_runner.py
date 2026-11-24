from __future__ import annotations

from app.core.config import Settings
from app.db.enums import ScanTool
from app.services.external_runner import (
    build_external_argv,
    summarize_external_output,
)


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        dig_binary="dig-test",
        whois_binary="whois-test",
        whatweb_binary="whatweb-test",
        curl_binary="curl-test",
    )


def test_fixed_argv_for_each_external_tool() -> None:
    settings = _settings()
    dig = build_external_argv(ScanTool.DIG, "example.test", 60, settings)
    assert dig[0] == "dig-test"
    assert dig[-2:] == ["example.test", "A"]
    assert "+short" in dig

    whois = build_external_argv(ScanTool.WHOIS, "example.test", 60, settings)
    assert whois == ["whois-test", "example.test"]

    whatweb = build_external_argv(
        ScanTool.WHATWEB, "http://127.0.0.1:3000/", 60, settings
    )
    assert whatweb[0] == "whatweb-test"
    assert "--aggression" in whatweb
    assert whatweb[whatweb.index("--aggression") + 1] == "1"
    assert "--follow-redirect=never" in whatweb
    assert whatweb[-1] == "http://127.0.0.1:3000/"

    curl = build_external_argv(
        ScanTool.CURL, "http://127.0.0.1:3000/", 60, settings
    )
    assert curl[0] == "curl-test"
    assert "--include" in curl
    assert "--max-redirs" in curl
    assert curl[curl.index("--max-redirs") + 1] == "0"
    assert curl[-1] == "http://127.0.0.1:3000/"


def test_dig_summary_keeps_records_by_type() -> None:
    summary = summarize_external_output(
        ScanTool.DIG,
        b"; A\n93.184.216.34\n; AAAA\n2001:db8::1\n; MX\n10 mail.example.test.\n",
    )
    assert summary["records"] == {
        "A": ["93.184.216.34"],
        "AAAA": ["2001:db8::1"],
        "MX": ["10 mail.example.test."],
    }
    assert summary["record_count"] == 3


def test_whois_summary_extracts_fields() -> None:
    summary = summarize_external_output(
        ScanTool.WHOIS,
        b"Domain Name: EXAMPLE.TEST\nRegistrar: Example\nCreation Date: 2020-01-01\n",
    )
    assert summary["fields"]["Registrar"] == "Example"
    assert summary["fields"]["Creation Date"] == "2020-01-01"
    assert summary["line_count"] == 3


def test_whatweb_summary_extracts_technologies_and_status() -> None:
    summary = summarize_external_output(
        ScanTool.WHATWEB,
        b'[{"target":"http://127.0.0.1:3000/","http_status":200,'
        b'"plugins":{"HTTPServer":{"version":["nginx/1.24.0"]},'
        b'"PHP":{"version":["8.2"]}}}]',
    )
    assert summary["status_code"] == 200
    assert summary["technologies"] == {
        "HTTPServer": ["nginx/1.24.0"],
        "PHP": ["8.2"],
    }


def test_curl_summary_extracts_status_headers_and_size() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        b"Location: /\r\n\r\nhello"
    )
    summary = summarize_external_output(ScanTool.CURL, raw)
    assert summary["status_code"] == 200
    assert summary["content_type"] == "text/html; charset=utf-8"
    assert summary["header_count"] == 2
    assert summary["body_bytes"] == 5
    assert summary["location"] == "/"
