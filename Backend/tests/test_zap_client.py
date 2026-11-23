from __future__ import annotations

import httpx
import pytest
from app.core.config import Settings
from app.services.zap_client import ZapClient, ZapError, ZapUnavailable


def _settings(**overrides) -> Settings:
    values = {
        "zap_base_url": "http://zap.test:8090",
        "zap_api_key": "test-zap-key",
        "zap_timeout_seconds": 5,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _client(handler, **kwargs) -> ZapClient:
    return ZapClient(
        _settings(), transport=httpx.MockTransport(handler), backoff_seconds=0, **kwargs
    )


async def test_uses_api_key_header_and_expected_endpoints() -> None:
    seen: list[tuple[str, dict[str, str], str | None]] = []
    responses = {
        "/JSON/core/view/version/": {"version": "2.17.0"},
        "/JSON/context/action/newContext/": {"contextId": "7"},
        "/JSON/context/action/removeContext/": {},
        "/JSON/context/action/includeInContext/": {},
        "/JSON/context/action/excludeFromContext/": {},
        "/JSON/spider/action/scan/": {"scan": "11"},
        "/JSON/spider/view/status/": {"status": "100"},
        "/JSON/spider/action/stop/": {},
        "/JSON/pscan/view/recordsToScan/": {"recordsToScan": "0"},
        "/JSON/ascan/action/scan/": {"scan": "12"},
        "/JSON/ascan/view/status/": {"status": "100"},
        "/JSON/ascan/action/stop/": {},
        "/JSON/alert/view/alerts/": {"alerts": [{"pluginId": "10020"}]},
        "/JSON/core/view/message/": {"message": {"id": "101"}},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.url.path,
                dict(request.url.params),
                request.headers.get("x-zap-api-key"),
            )
        )
        return httpx.Response(200, json=responses[request.url.path])

    async with _client(handler) as client:
        assert await client.version() == "2.17.0"
        assert await client.new_context("penpal-scan-1") == "7"
        await client.include_in_context("penpal-scan-1", r"http://127\.0\.0\.1:3000/.*")
        await client.exclude_from_context("penpal-scan-1", r".*/logout")
        assert await client.spider_scan("http://127.0.0.1:3000/", "penpal-scan-1") == 11
        assert await client.spider_status(11) == 100
        await client.spider_stop(11)
        assert await client.records_to_scan() == 0
        assert await client.active_scan("http://127.0.0.1:3000/", "7") == 12
        assert await client.active_status(12) == 100
        await client.active_stop(12)
        alerts = await client.alerts("http://127.0.0.1:3000/", 40, 20)
        assert alerts == [{"pluginId": "10020"}]
        assert await client.message("101") == {"id": "101"}

    assert all(entry[2] == "test-zap-key" for entry in seen)
    assert [entry[0] for entry in seen] == [
        "/JSON/core/view/version/",
        "/JSON/context/action/newContext/",
        "/JSON/context/action/includeInContext/",
        "/JSON/context/action/excludeFromContext/",
        "/JSON/spider/action/scan/",
        "/JSON/spider/view/status/",
        "/JSON/spider/action/stop/",
        "/JSON/pscan/view/recordsToScan/",
        "/JSON/ascan/action/scan/",
        "/JSON/ascan/view/status/",
        "/JSON/ascan/action/stop/",
        "/JSON/alert/view/alerts/",
        "/JSON/core/view/message/",
    ]
    assert seen[1][1] == {"contextName": "penpal-scan-1"}
    assert seen[2][1]["contextName"] == "penpal-scan-1"
    assert seen[3][1]["contextName"] == "penpal-scan-1"
    assert seen[4][1]["contextName"] == "penpal-scan-1"
    assert seen[4][1]["recurse"] == "true"
    assert seen[5][1] == {"scanId": "11"}
    assert seen[8][1] == {"url": "http://127.0.0.1:3000/", "contextId": "7", "recurse": "true"}
    assert seen[11][1] == {
        "baseurl": "http://127.0.0.1:3000/",
        "start": "40",
        "count": "20",
    }
    assert seen[12][1] == {"id": "101"}


async def test_active_scan_options_use_integer_parameter() -> None:
    seen: list[tuple[str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, dict(request.url.params)))
        return httpx.Response(200, json={})

    async with _client(handler) as client:
        await client.configure_active_scan(_settings())

    assert [path for path, _ in seen] == [
        "/JSON/ascan/action/setOptionThreadPerHost/",
        "/JSON/ascan/action/setOptionMaxRuleDurationInMins/",
        "/JSON/ascan/action/setOptionMaxScanDurationInMins/",
        "/JSON/ascan/action/setOptionMaxAlertsPerRule/",
    ]
    assert [params["Integer"] for _, params in seen] == ["1", "1", "30", "10"]


async def test_retries_server_errors_then_succeeds() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(503, text="starting")
        return httpx.Response(200, json={"version": "2.17.0"})

    async with _client(handler, retries=3) as client:
        assert await client.version() == "2.17.0"
    assert calls == 3


async def test_exhausted_retries_raise_unavailable() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500, text="boom")

    async with _client(handler, retries=2) as client:
        with pytest.raises(ZapUnavailable, match="failed after 2 attempts"):
            await client.version()
    assert calls == 2


async def test_transport_failure_raises_unavailable() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("connection refused", request=request)

    async with _client(handler, retries=2) as client:
        with pytest.raises(ZapUnavailable, match="connection failed"):
            await client.version()
    assert calls == 2


async def test_client_errors_are_not_retried() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(403, text="bad key")

    async with _client(handler, retries=3) as client:
        with pytest.raises(ZapError, match="HTTP 403"):
            await client.version()
    assert calls == 1


async def test_invalid_json_and_error_payloads_raise() -> None:
    def invalid_json(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    async with _client(invalid_json) as client:
        with pytest.raises(ZapError, match="invalid JSON"):
            await client.version()

    def error_payload(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"code": "bad_view", "message": "no such view"})

    async with _client(error_payload) as client:
        with pytest.raises(ZapError, match="no such view"):
            await client.version()

    def wrong_shape(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    async with _client(wrong_shape) as client:
        with pytest.raises(ZapError, match="unexpected payload"):
            await client.version()


async def test_malformed_view_payloads_raise() -> None:
    def no_context_id(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    async with _client(no_context_id) as client:
        with pytest.raises(ZapError, match="context id"):
            await client.new_context("penpal-scan-1")

    def alerts_not_a_list(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"alerts": "nope"})

    async with _client(alerts_not_a_list) as client:
        with pytest.raises(ZapError, match="alerts list"):
            await client.alerts("http://127.0.0.1:3000/", 0, 10)

    def message_not_an_object(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "nope"})

    async with _client(message_not_an_object) as client:
        with pytest.raises(ZapError, match="message object"):
            await client.message("101")
