"""Small ZAP REST client.

Only the endpoints PenPal needs are wrapped. Endpoint names and parameters were
checked against the ZAP 2.17 API catalogue. The API key travels in the
``X-ZAP-API-Key`` header so it never appears in a URL or a log line.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.core.config import Settings

logger = logging.getLogger(__name__)


class ZapError(RuntimeError):
    """ZAP returned an error or unusable data."""


class ZapUnavailable(ZapError):
    """ZAP could not be reached or kept returning server errors."""


class ZapClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        retries: int = 3,
        backoff_seconds: float = 0.5,
    ) -> None:
        self.base_url = settings.zap_base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=float(settings.zap_timeout_seconds),
            headers={
                "Accept": "application/json",
                "X-ZAP-API-Key": settings.zap_api_key,
            },
            transport=transport,
        )
        self.retries = max(1, retries)
        self.backoff_seconds = max(0.0, backoff_seconds)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> ZapClient:
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.aclose()

    async def _request(
        self, component: str, kind: str, name: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        path = f"/JSON/{component}/{kind}/{name}/"
        last_error: str | None = None
        for attempt in range(self.retries):
            try:
                response = await self._client.get(path, params=params or {})
            except httpx.TransportError:
                last_error = "connection failed"
            else:
                if response.status_code >= 500:
                    last_error = f"HTTP {response.status_code}"
                elif response.status_code >= 400:
                    raise ZapError(
                        f"ZAP returned HTTP {response.status_code} for {component}/{name}"
                    )
                else:
                    try:
                        data = response.json()
                    except ValueError as exc:
                        raise ZapError(
                            f"ZAP returned invalid JSON for {component}/{name}"
                        ) from exc
                    if not isinstance(data, dict):
                        raise ZapError(
                            f"ZAP returned an unexpected payload for {component}/{name}"
                        )
                    if data.get("code") and data.get("message"):
                        raise ZapError(
                            f"ZAP error for {component}/{name}: {data['message']} "
                            f"({data['code']})"
                        )
                    return data
            if attempt + 1 < self.retries:
                await asyncio.sleep(self.backoff_seconds * (2**attempt))
        raise ZapUnavailable(
            f"ZAP request {component}/{name} failed after {self.retries} attempts "
            f"({last_error or 'unknown error'})"
        )

    async def _action(
        self, component: str, name: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request(component, "action", name, params)

    async def _view(
        self, component: str, name: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._request(component, "view", name, params)

    @staticmethod
    def _as_int(value: Any, default: int = 0) -> int:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return default

    async def version(self) -> str:
        data = await self._view("core", "version")
        return str(data.get("version") or "unknown")

    async def new_session(self, name: str) -> None:
        await self._action("core", "newSession", {"name": name, "overwrite": "true"})

    async def new_context(self, name: str) -> str:
        data = await self._action("context", "newContext", {"contextName": name})
        context_id = data.get("contextId")
        if context_id is None:
            raise ZapError("ZAP did not return a context id")
        return str(context_id)

    async def remove_context(self, name: str) -> None:
        await self._action("context", "removeContext", {"contextName": name})

    async def include_in_context(self, name: str, regex: str) -> None:
        await self._action(
            "context", "includeInContext", {"contextName": name, "regex": regex}
        )

    async def exclude_from_context(self, name: str, regex: str) -> None:
        await self._action(
            "context", "excludeFromContext", {"contextName": name, "regex": regex}
        )

    async def spider_scan(self, url: str, context_name: str) -> int:
        data = await self._action(
            "spider",
            "scan",
            {"url": url, "contextName": context_name, "recurse": "true"},
        )
        return self._as_int(data.get("scan"))

    async def spider_status(self, scan_id: int) -> int:
        data = await self._view("spider", "status", {"scanId": str(scan_id)})
        return self._as_int(data.get("status"))

    async def spider_stop(self, scan_id: int) -> None:
        await self._action("spider", "stop", {"scanId": str(scan_id)})

    async def records_to_scan(self) -> int:
        data = await self._view("pscan", "recordsToScan")
        return self._as_int(data.get("recordsToScan"), default=-1)

    async def configure_active_scan(self, settings: Settings) -> None:
        await self._action(
            "ascan",
            "setOptionThreadPerHost",
            {"Integer": str(settings.zap_active_threads_per_host)},
        )
        await self._action(
            "ascan",
            "setOptionMaxRuleDurationInMins",
            {"Integer": str(settings.zap_active_max_rule_minutes)},
        )
        await self._action(
            "ascan",
            "setOptionMaxScanDurationInMins",
            {"Integer": str(settings.zap_active_max_scan_minutes)},
        )
        await self._action(
            "ascan",
            "setOptionMaxAlertsPerRule",
            {"Integer": str(settings.zap_active_max_alerts_per_rule)},
        )

    async def active_scan(self, url: str, context_id: str) -> int:
        data = await self._action(
            "ascan",
            "scan",
            {"url": url, "contextId": context_id, "recurse": "true"},
        )
        return self._as_int(data.get("scan"))

    async def active_status(self, scan_id: int) -> int:
        data = await self._view("ascan", "status", {"scanId": str(scan_id)})
        return self._as_int(data.get("status"))

    async def active_stop(self, scan_id: int) -> None:
        await self._action("ascan", "stop", {"scanId": str(scan_id)})

    async def alerts(self, base_url: str, start: int, count: int) -> list[dict[str, Any]]:
        data = await self._view(
            "alert",
            "alerts",
            {"baseurl": base_url, "start": str(start), "count": str(count)},
        )
        alerts = data.get("alerts")
        if not isinstance(alerts, list):
            raise ZapError("ZAP did not return an alerts list")
        return [alert for alert in alerts if isinstance(alert, dict)]

    async def message(self, message_id: str | int) -> dict[str, Any]:
        data = await self._view("core", "message", {"id": str(message_id)})
        message = data.get("message")
        if not isinstance(message, dict):
            raise ZapError("ZAP did not return a message object")
        return message
