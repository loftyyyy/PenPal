"""Deterministic tool runners used by API tests. No process or network access."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.db.enums import NmapProfile
from app.services.nmap_runner import NmapRunResult, ScanCancelled

FIXTURES = Path(__file__).parent / "fixtures"
NMAP_FIXTURE = FIXTURES / "nmap_lsrs.xml"


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
