"""Run one ZAP scan through the REST API and capture its raw output."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from app.core.config import Settings
from app.db.enums import ZapProfile
from app.db.models import Scan
from app.services.nmap_runner import ScanCancelled, ScanTimeout
from app.services.scan_manager import RawOutput
from app.services.zap_client import ZapClient, ZapError

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int], Awaitable[None]]
StatusReader = Callable[[int], Awaitable[int]]
StopAction = Callable[[int], Awaitable[None]]


def _truncate(value: Any, limit: int) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "\n[truncated]"
    return value


class ZapScanRunner:
    """Orchestrates spider, passive scan, optional active scan and alert export."""

    def __init__(
        self,
        settings: Settings,
        *,
        client_factory: Callable[[], Any] | None = None,
        poll_interval: float | None = None,
    ) -> None:
        self.settings = settings
        self._client_factory = client_factory or (lambda: ZapClient(settings))
        self.poll_interval = (
            settings.zap_poll_interval_seconds
            if poll_interval is None
            else max(0.0, poll_interval)
        )

    async def run(
        self,
        *,
        scan: Scan,
        context_include: list[str],
        context_exclude: list[str],
        timeout_seconds: int,
        cancel_event: asyncio.Event,
        progress: ProgressCallback,
    ) -> RawOutput:
        deadline = time.monotonic() + max(1, timeout_seconds)
        client = self._client_factory()
        context_name = f"penpal-scan-{scan.id}"
        context_created = False
        try:
            version = await client.version()
            await progress(3)
            await client.new_session(context_name)
            context_id = await client.new_context(context_name)
            context_created = True
            for regex in context_include:
                await client.include_in_context(context_name, regex)
            for regex in context_exclude:
                await client.exclude_from_context(context_name, regex)
            await progress(8)

            spider_id = await client.spider_scan(scan.target, context_name)
            await self._poll(
                client.spider_status,
                spider_id,
                label="spider",
                deadline=deadline,
                cancel_event=cancel_event,
                progress=progress,
                start=10,
                end=40,
                stop=client.spider_stop,
            )
            await self._drain_passive(
                client, deadline=deadline, cancel_event=cancel_event, progress=progress
            )

            if ZapProfile(scan.profile) == ZapProfile.ACTIVE_LIMITED:
                await client.configure_active_scan(self.settings)
                active_id = await client.active_scan(scan.target, context_id)
                await self._poll(
                    client.active_status,
                    active_id,
                    label="active scan",
                    deadline=deadline,
                    cancel_event=cancel_event,
                    progress=progress,
                    start=65,
                    end=90,
                    stop=client.active_stop,
                )

            await progress(92)
            alerts = await self._fetch_alerts(client, scan.target, cancel_event)
            await progress(96)
            alerts = await self._attach_messages(
                client, alerts, cancel_event=cancel_event
            )
            await progress(99)

            document = {
                "tool": "zap",
                "version": version,
                "profile": scan.profile,
                "target": scan.target,
                "context": {
                    "name": context_name,
                    "id": context_id,
                    "include": context_include,
                    "exclude": context_exclude,
                },
                "counts": self._risk_counts(alerts),
                "alerts": alerts,
            }
            return RawOutput(
                data=json.dumps(document, indent=2, sort_keys=True, default=str).encode(
                    "utf-8"
                ),
                filename="zap.json",
                tool_version=version,
            )
        finally:
            if context_created:
                try:
                    await client.remove_context(context_name)
                except (ZapError, OSError):
                    logger.debug("Could not remove ZAP context %s", context_name)
            close = getattr(client, "aclose", None)
            if close is not None:
                try:
                    await close()
                except Exception:  # pragma: no cover - transport dependent
                    logger.debug("Could not close the ZAP client", exc_info=True)

    async def _poll(
        self,
        read: StatusReader,
        job_id: int,
        *,
        label: str,
        deadline: float,
        cancel_event: asyncio.Event,
        progress: ProgressCallback,
        start: int,
        end: int,
        stop: StopAction,
    ) -> None:
        last_value = -1
        while True:
            if cancel_event.is_set():
                await self._stop(stop, job_id)
                raise ScanCancelled("scan cancelled")
            if time.monotonic() >= deadline:
                await self._stop(stop, job_id)
                raise ScanTimeout(f"ZAP {label} exceeded the scan timeout")
            value = await read(job_id)
            if value != last_value:
                span = max(0, end - start)
                await progress(start + int(span * min(100, max(0, value)) / 100))
                last_value = value
            if value >= 100:
                return
            await self._pause(cancel_event)

    async def _drain_passive(
        self,
        client: Any,
        *,
        deadline: float,
        cancel_event: asyncio.Event,
        progress: ProgressCallback,
    ) -> None:
        await progress(45)
        while True:
            if cancel_event.is_set():
                raise ScanCancelled("scan cancelled")
            if time.monotonic() >= deadline:
                raise ScanTimeout("ZAP passive scan exceeded the scan timeout")
            remaining = await client.records_to_scan()
            if remaining <= 0:
                break
            await self._pause(cancel_event)
        await progress(65)

    async def _pause(self, cancel_event: asyncio.Event) -> None:
        if self.poll_interval <= 0:
            await asyncio.sleep(0)
            return
        try:
            await asyncio.wait_for(cancel_event.wait(), timeout=self.poll_interval)
        except TimeoutError:
            return
        raise ScanCancelled("scan cancelled")

    @staticmethod
    async def _stop(stop: StopAction, job_id: int) -> None:
        try:
            await stop(job_id)
        except (ZapError, OSError):
            logger.debug("Could not stop ZAP job %s", job_id)

    async def _fetch_alerts(
        self, client: Any, base_url: str, cancel_event: asyncio.Event
    ) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        page_size = max(1, self.settings.zap_alert_page_size)
        max_alerts = max(1, self.settings.zap_max_alerts)
        start = 0
        while len(alerts) < max_alerts:
            if cancel_event.is_set():
                raise ScanCancelled("scan cancelled")
            batch = await client.alerts(
                base_url, start, min(page_size, max_alerts - len(alerts))
            )
            if not batch:
                break
            alerts.extend(batch)
            start += len(batch)
            if len(batch) < page_size:
                break
        return alerts

    async def _attach_messages(
        self,
        client: Any,
        alerts: list[dict[str, Any]],
        *,
        cancel_event: asyncio.Event,
    ) -> list[dict[str, Any]]:
        limit = max(0, self.settings.zap_max_message_fetches)
        max_chars = max(0, self.settings.zap_message_max_chars)
        enriched: list[dict[str, Any]] = []
        cache: dict[str, dict[str, Any] | None] = {}
        fetched = 0
        for alert in alerts:
            item = dict(alert)
            message_id = item.get("messageId")
            if message_id:
                key = str(message_id)
                if key not in cache and fetched < limit:
                    if cancel_event.is_set():
                        raise ScanCancelled("scan cancelled")
                    try:
                        cache[key] = await client.message(message_id)
                    except (ZapError, OSError):
                        logger.debug("Could not fetch ZAP message %s", message_id)
                        cache[key] = None
                    fetched += 1
                message = cache.get(key)
                if message is not None:
                    item["httpMessage"] = {
                        field: _truncate(message.get(field), max_chars)
                        for field in (
                            "requestHeader",
                            "requestBody",
                            "responseHeader",
                            "responseBody",
                        )
                        if message.get(field) is not None
                    }
            enriched.append(item)
        return enriched

    @staticmethod
    def _risk_counts(alerts: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"alerts": len(alerts), "high": 0, "medium": 0, "low": 0, "info": 0}
        for alert in alerts:
            risk = str(alert.get("risk") or "").strip().lower()
            if risk == "high":
                counts["high"] += 1
            elif risk == "medium":
                counts["medium"] += 1
            elif risk == "low":
                counts["low"] += 1
            else:
                counts["info"] += 1
        return counts
