"""Deterministic tool runners used by API tests. No process or network access."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.db.enums import NmapProfile
from app.services.ai.base import AIProvider, ProviderResult
from app.services.nmap_runner import NmapRunResult, ScanCancelled
from app.services.scan_manager import RawOutput

FIXTURES = Path(__file__).parent / "fixtures"
NMAP_FIXTURE = FIXTURES / "nmap_lsrs.xml"
ZAP_ALERTS_FIXTURE = FIXTURES / "zap_alerts.json"
ZAP_MESSAGE_FIXTURE = FIXTURES / "zap_message.json"


@dataclass
class FakeNmapRunner:
    """Returns fixture XML, or waits on a gate so cancellation can be tested."""

    xml_bytes: bytes = field(default_factory=lambda: NMAP_FIXTURE.read_bytes())
    gate: asyncio.Event | None = None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    started: asyncio.Event = field(default_factory=asyncio.Event)

    async def run(
        self,
        *,
        profile: NmapProfile,
        host: str,
        ports: list[int],
        timeout_seconds: int,
        cancel_event: asyncio.Event,
    ) -> NmapRunResult:
        self.calls.append(
            {
                "profile": profile,
                "host": host,
                "ports": list(ports),
                "timeout_seconds": timeout_seconds,
            }
        )
        self.started.set()
        if self.error is not None:
            raise self.error
        if self.gate is not None:
            gate_waiter = asyncio.create_task(self.gate.wait())
            cancel_waiter = asyncio.create_task(cancel_event.wait())
            try:
                await asyncio.wait(
                    {gate_waiter, cancel_waiter},
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                gate_waiter.cancel()
                cancel_waiter.cancel()
        if cancel_event.is_set():
            raise ScanCancelled("scan cancelled")
        return NmapRunResult(
            raw_xml=self.xml_bytes,
            argv=["nmap", host],
            return_code=0,
            stderr="",
        )


def load_zap_alerts() -> list[dict[str, Any]]:
    return json.loads(ZAP_ALERTS_FIXTURE.read_text(encoding="utf-8"))


class ScriptedProvider(AIProvider):
    """Replays scripted outputs or exceptions and records every prompt."""

    def __init__(
        self,
        outputs: list[str | Exception],
        *,
        name: str = "scripted",
        model: str = "scripted-model",
    ) -> None:
        self.name = name
        self.model = model
        self.outputs = list(outputs)
        self.calls: list[dict[str, str]] = []
        self.active = 0
        self.max_active = 0
        self.gate: asyncio.Event | None = None

    async def complete_json(
        self, system: str, user: str, *, max_tokens: int
    ) -> ProviderResult:
        self.calls.append(
            {"system": system, "user": user, "max_tokens": str(max_tokens)}
        )
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.gate is not None:
                await self.gate.wait()
            if not self.outputs:
                raise AssertionError("ScriptedProvider ran out of outputs")
            item = self.outputs.pop(0)
            if isinstance(item, Exception):
                raise item
            return ProviderResult(
                content=item,
                prompt_tokens=10,
                completion_tokens=20,
                provider=self.name,
                model=self.model,
            )
        finally:
            self.active -= 1


@dataclass
class FakeZapRunner:
    """Returns a ZAP-shaped JSON document built from fixtures, or waits on a gate."""

    alerts: list[dict[str, Any]] = field(default_factory=load_zap_alerts)
    messages: dict[str, Any] = field(
        default_factory=lambda: json.loads(
            ZAP_MESSAGE_FIXTURE.read_text(encoding="utf-8")
        )
    )
    version: str = "2.17.0"
    gate: asyncio.Event | None = None
    error: Exception | None = None
    raw_document: bytes | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    started: asyncio.Event = field(default_factory=asyncio.Event)

    async def run(
        self,
        *,
        scan: Any,
        context_include: list[str],
        context_exclude: list[str],
        timeout_seconds: int,
        cancel_event: asyncio.Event,
        progress: Any,
    ) -> RawOutput:
        self.calls.append(
            {
                "scan_id": scan.id,
                "profile": scan.profile,
                "target": scan.target,
                "context_include": list(context_include),
                "context_exclude": list(context_exclude),
                "timeout_seconds": timeout_seconds,
            }
        )
        self.started.set()
        if self.error is not None:
            raise self.error
        if self.gate is not None:
            gate_waiter = asyncio.create_task(self.gate.wait())
            cancel_waiter = asyncio.create_task(cancel_event.wait())
            try:
                await asyncio.wait(
                    {gate_waiter, cancel_waiter},
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                gate_waiter.cancel()
                cancel_waiter.cancel()
        if cancel_event.is_set():
            raise ScanCancelled("scan cancelled")
        await progress(50)

        if self.raw_document is not None:
            data = self.raw_document
        else:
            data = json.dumps(self.document(scan), default=str).encode("utf-8")
        return RawOutput(data=data, filename="zap.json", tool_version=self.version)

    def document(self, scan: Any) -> dict[str, Any]:
        counts = {"alerts": len(self.alerts), "high": 0, "medium": 0, "low": 0, "info": 0}
        for alert in self.alerts:
            risk = str(alert.get("risk") or "").strip().lower()
            if risk in {"high", "medium", "low"}:
                counts[risk] += 1
            else:
                counts["info"] += 1
        alerts: list[dict[str, Any]] = []
        for alert in self.alerts:
            item = dict(alert)
            if item.get("messageId"):
                item["httpMessage"] = {
                    key: self.messages.get(key)
                    for key in (
                        "requestHeader",
                        "requestBody",
                        "responseHeader",
                        "responseBody",
                    )
                    if self.messages.get(key) is not None
                }
            alerts.append(item)
        return {
            "tool": "zap",
            "version": self.version,
            "profile": scan.profile,
            "target": scan.target,
            "context": {"name": f"penpal-scan-{scan.id}", "include": []},
            "counts": counts,
            "alerts": alerts,
        }
