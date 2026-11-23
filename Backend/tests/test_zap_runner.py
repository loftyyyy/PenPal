from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from app.core.config import Settings
from app.db.enums import ZapProfile
from app.services.nmap_runner import ScanCancelled, ScanTimeout
from app.services.zap_client import ZapError
from app.services.zap_runner import ZapScanRunner
from tests.fakes import ZAP_MESSAGE_FIXTURE, load_zap_alerts


class FakeScan:
    id = 42
    profile = ZapProfile.BASELINE.value
    target = "http://127.0.0.1:3000/"

    def __init__(self, profile: str = ZapProfile.BASELINE.value) -> None:
        self.profile = profile


class FakeZapClient:
    def __init__(
        self,
        *,
        spider_statuses: list[int] | None = None,
        records: list[int] | None = None,
        active_statuses: list[int] | None = None,
        alert_pages: list[list[dict[str, Any]]] | None = None,
        message: dict[str, Any] | None = None,
    ) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.spider_statuses = list(spider_statuses or [0, 50, 100])
        self.records = list(records if records is not None else [2, 0])
        self.active_statuses = list(active_statuses or [100])
        self.alert_pages = list(alert_pages or [load_zap_alerts()])
        self.message_payload = message or json.loads(
            ZAP_MESSAGE_FIXTURE.read_text(encoding="utf-8")
        )
        self.removed: list[str] = []
        self.closed = False

    def _record(self, name: str, *args: Any) -> None:
        self.calls.append((name, args))

    async def version(self) -> str:
        self._record("version")
        return "2.17.0"

    async def new_session(self, name: str) -> None:
        self._record("new_session", name)

    async def new_context(self, name: str) -> str:
        self._record("new_context", name)
        return "7"

    async def remove_context(self, name: str) -> None:
        self.removed.append(name)
        self._record("remove_context", name)

    async def include_in_context(self, name: str, regex: str) -> None:
        self._record("include", name, regex)

    async def exclude_from_context(self, name: str, regex: str) -> None:
        self._record("exclude", name, regex)

    async def spider_scan(self, url: str, context_name: str) -> int:
        self._record("spider_scan", url, context_name)
        return 11

    async def spider_status(self, scan_id: int) -> int:
        self._record("spider_status", scan_id)
        return self.spider_statuses.pop(0) if len(self.spider_statuses) > 1 else 100

    async def spider_stop(self, scan_id: int) -> None:
        self._record("spider_stop", scan_id)

    async def records_to_scan(self) -> int:
        self._record("records_to_scan")
        return self.records.pop(0) if self.records else 0

    async def configure_active_scan(self, settings: Settings) -> None:
        self._record("configure_active_scan")

    async def active_scan(self, url: str, context_id: str) -> int:
        self._record("active_scan", url, context_id)
        return 12

    async def active_status(self, scan_id: int) -> int:
        self._record("active_status", scan_id)
        return (
            self.active_statuses.pop(0) if len(self.active_statuses) > 1 else 100
        )

    async def active_stop(self, scan_id: int) -> None:
        self._record("active_stop", scan_id)

    async def alerts(self, base_url: str, start: int, count: int) -> list[dict[str, Any]]:
        self._record("alerts", base_url, start, count)
        return self.alert_pages.pop(0) if self.alert_pages else []

    async def message(self, message_id: str | int) -> dict[str, Any]:
        self._record("message", message_id)
        return self.message_payload

    async def aclose(self) -> None:
        self.closed = True


def _settings(**overrides) -> Settings:
    values = {
        "zap_base_url": "http://zap.test:8090",
        "zap_api_key": "test-zap-key",
        "zap_poll_interval_seconds": 0,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _runner(client: FakeZapClient, **overrides) -> ZapScanRunner:
    return ZapScanRunner(
        _settings(**overrides), client_factory=lambda: client, poll_interval=0
    )


def _names(client: FakeZapClient) -> list[str]:
    return [name for name, _ in client.calls]


async def test_baseline_scan_builds_context_and_exports_alerts() -> None:
    client = FakeZapClient()
    runner = _runner(client)
    progress: list[int] = []

    async def report(value: int) -> None:
        progress.append(value)

    result = await runner.run(
        scan=FakeScan(),
        context_include=[r"http://127\.0\.0\.1:3000/.*"],
        context_exclude=[r".*/logout"],
        timeout_seconds=60,
        cancel_event=asyncio.Event(),
        progress=report,
    )

    names = _names(client)
    assert names[:4] == ["version", "new_session", "new_context", "include"]
    assert ("include", ("penpal-scan-42", r"http://127\.0\.0\.1:3000/.*")) in client.calls
    assert ("exclude", ("penpal-scan-42", r".*/logout")) in client.calls
    assert ("spider_scan", ("http://127.0.0.1:3000/", "penpal-scan-42")) in client.calls
    assert "active_scan" not in names
    assert "configure_active_scan" not in names
    assert names.count("message") == 3
    assert client.removed == ["penpal-scan-42"]
    assert client.closed is True
    assert progress == sorted(progress)
    assert progress[-1] == 99

    document = json.loads(result.data)
    assert result.filename == "zap.json"
    assert result.tool_version == "2.17.0"
    assert document["tool"] == "zap"
    assert document["version"] == "2.17.0"
    assert document["profile"] == "baseline"
    assert document["target"] == "http://127.0.0.1:3000/"
    assert document["context"]["name"] == "penpal-scan-42"
    assert document["context"]["id"] == "7"
    assert document["counts"] == {
        "alerts": 5,
        "high": 2,
        "medium": 1,
        "low": 1,
        "info": 1,
    }
    assert len(document["alerts"]) == 5
    assert "requestHeader" in document["alerts"][0]["httpMessage"]


async def test_active_limited_configures_before_active_scan() -> None:
    client = FakeZapClient(active_statuses=[20, 80, 100])
    runner = _runner(client)

    async def report(_value: int) -> None:
        return None

    await runner.run(
        scan=FakeScan(ZapProfile.ACTIVE_LIMITED.value),
        context_include=["http://127.0.0.1:3000/.*"],
        context_exclude=[],
        timeout_seconds=60,
        cancel_event=asyncio.Event(),
        progress=report,
    )

    names = _names(client)
    assert names.index("configure_active_scan") < names.index("active_scan")
    assert ("active_scan", ("http://127.0.0.1:3000/", "7")) in client.calls
    assert names.count("active_status") == 3


async def test_cancel_stops_running_spider_and_cleans_up() -> None:
    client = FakeZapClient()
    runner = _runner(client)
    cancel_event = asyncio.Event()
    cancel_event.set()

    async def report(_value: int) -> None:
        return None

    with pytest.raises(ScanCancelled):
        await runner.run(
            scan=FakeScan(),
            context_include=[],
            context_exclude=[],
            timeout_seconds=60,
            cancel_event=cancel_event,
            progress=report,
        )

    assert ("spider_stop", (11,)) in client.calls
    assert client.removed == ["penpal-scan-42"]
    assert client.closed is True


async def test_timeout_stops_running_spider(monkeypatch: pytest.MonkeyPatch) -> None:
    class FrozenTime:
        def __init__(self) -> None:
            self.now = 10_000.0

        def monotonic(self) -> float:
            self.now += 100.0
            return self.now

    monkeypatch.setattr("app.services.zap_runner.time", FrozenTime())

    client = FakeZapClient(spider_statuses=[0])
    runner = _runner(client)

    async def report(_value: int) -> None:
        return None

    with pytest.raises(ScanTimeout, match="spider"):
        await runner.run(
            scan=FakeScan(),
            context_include=[],
            context_exclude=[],
            timeout_seconds=5,
            cancel_event=asyncio.Event(),
            progress=report,
        )
    assert ("spider_stop", (11,)) in client.calls
    assert client.removed == ["penpal-scan-42"]


async def test_alert_pagination_respects_page_size_and_cap() -> None:
    alerts = load_zap_alerts()
    client = FakeZapClient(
        alert_pages=[[alerts[0], alerts[1]], [alerts[2]]],
    )
    runner = _runner(client, zap_alert_page_size=2, zap_max_alerts=3)

    async def report(_value: int) -> None:
        return None

    result = await runner.run(
        scan=FakeScan(),
        context_include=[],
        context_exclude=[],
        timeout_seconds=60,
        cancel_event=asyncio.Event(),
        progress=report,
    )

    alert_calls = [call for call in client.calls if call[0] == "alerts"]
    assert alert_calls == [
        ("alerts", ("http://127.0.0.1:3000/", 0, 2)),
        ("alerts", ("http://127.0.0.1:3000/", 2, 1)),
    ]
    document = json.loads(result.data)
    assert len(document["alerts"]) == 3


async def test_message_fetch_limit_and_truncation() -> None:
    alerts = load_zap_alerts()
    first_alert = dict(alerts[0], messageId="201")
    second_alert = dict(alerts[1], messageId="202")
    long_message = {
        "requestHeader": "A" * 500,
        "requestBody": "B" * 500,
        "responseHeader": "C" * 500,
        "responseBody": "D" * 500,
    }
    client = FakeZapClient(
        alert_pages=[[first_alert, second_alert]], message=long_message
    )
    runner = _runner(
        client, zap_max_message_fetches=1, zap_message_max_chars=10
    )

    async def report(_value: int) -> None:
        return None

    result = await runner.run(
        scan=FakeScan(),
        context_include=[],
        context_exclude=[],
        timeout_seconds=60,
        cancel_event=asyncio.Event(),
        progress=report,
    )

    message_calls = [call for call in client.calls if call[0] == "message"]
    assert message_calls == [("message", ("201",))]
    document = json.loads(result.data)
    first = document["alerts"][0]["httpMessage"]
    assert first["requestHeader"].endswith("[truncated]")
    assert len(first["requestHeader"]) == len("A" * 10 + "\n[truncated]")
    assert "httpMessage" not in document["alerts"][1]


async def test_message_failure_keeps_alert_without_evidence() -> None:
    alerts = load_zap_alerts()

    class BrokenMessageClient(FakeZapClient):
        async def message(self, message_id: str | int) -> dict[str, Any]:
            self._record("message", message_id)
            raise ZapError("message unavailable")

    client = BrokenMessageClient(alert_pages=[alerts[:1]])
    runner = _runner(client)

    async def report(_value: int) -> None:
        return None

    result = await runner.run(
        scan=FakeScan(),
        context_include=[],
        context_exclude=[],
        timeout_seconds=60,
        cancel_event=asyncio.Event(),
        progress=report,
    )

    document = json.loads(result.data)
    assert "httpMessage" not in document["alerts"][0]
