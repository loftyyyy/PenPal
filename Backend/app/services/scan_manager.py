"""Scan manager: in-process background jobs, limits, cancellation, recovery.

No Celery or Redis: the course project runs one backend process. Restart
recovery marks interrupted jobs failed so clients never wait forever.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.db.base import utcnow
from app.db.enums import (
    AssessmentStatus,
    NmapProfile,
    ScanStatus,
    ScanTool,
)
from app.db.models import Assessment, Scan, ScopeItem
from app.services import audit
from app.services.external_runner import (
    ExternalToolError,
    ExternalToolRunner,
    summarize_external_output,
)
from app.services.finding_normalizer import (
    WhatWebParseError,
    ZapParseError,
    normalize_nmap_result,
    normalize_whatweb_result,
    normalize_zap_result,
    parse_whatweb_document,
    parse_zap_document,
)
from app.services.nmap_parser import NmapParseError, NmapResult, parse_nmap_xml
from app.services.nmap_runner import (
    NmapRunError,
    NmapRunner,
    ScanCancelled,
    ScanTimeout,
)
from app.services.scope_guard import ScopeGuard
from app.services.storage import sha256_bytes, write_data_file
from app.services.zap_client import ZapError

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int], Awaitable[None]]


@dataclass
class RawOutput:
    data: bytes
    filename: str
    tool_version: str | None = None


WHOIS_SKIP_NOTE = (
    "not applicable for private/internal targets; no external lookup performed"
)


def _all_private(addresses: list[str]) -> bool:
    if not addresses:
        return False
    try:
        for value in addresses:
            address = ipaddress.ip_address(value)
            if not (
                address.is_private
                or address.is_loopback
                or address.is_link_local
            ):
                return False
    except ValueError:
        return False
    return True


def _risk_count(alerts: Any, risk: str) -> int:
    if not isinstance(alerts, list):
        return 0
    count = 0
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        value = str(alert.get("risk") or "").strip().lower()
        if (risk == "info" and value not in {"high", "medium", "low"}) or value == risk:
            count += 1
    return count


class NmapRunnerProtocol:
    async def run(
        self,
        *,
        profile: NmapProfile,
        host: str,
        ports: list[int],
        timeout_seconds: int,
        cancel_event: asyncio.Event,
    ) -> Any:  # pragma: no cover - protocol
        raise NotImplementedError


class ZapRunnerProtocol:
    async def run(
        self,
        *,
        scan: Scan,
        context_include: list[str],
        context_exclude: list[str],
        timeout_seconds: int,
        cancel_event: asyncio.Event,
        progress: ProgressCallback,
    ) -> RawOutput:  # pragma: no cover - protocol
        raise NotImplementedError


class ScanManager:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        nmap_runner: Any | None = None,
        zap_runner: Any | None = None,
        external_runner: ExternalToolRunner | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.nmap_runner = nmap_runner or NmapRunner(settings)
        self.zap_runner = zap_runner
        self.external_runner = external_runner
        self._tasks: dict[int, asyncio.Task[None]] = {}
        self._cancel_events: dict[int, asyncio.Event] = {}
        self._nmap_semaphore = asyncio.Semaphore(max(1, settings.nmap_max_concurrency))
        self._external_semaphore = asyncio.Semaphore(
            max(1, settings.nmap_max_concurrency)
        )
        self._zap_lock = asyncio.Lock()

    async def start(self, scan_id: int) -> None:
        if scan_id in self._tasks and not self._tasks[scan_id].done():
            return
        self._cancel_events.setdefault(scan_id, asyncio.Event())
        task = asyncio.create_task(self._run(scan_id), name=f"scan-{scan_id}")
        self._tasks[scan_id] = task
        task.add_done_callback(lambda _task: self._tasks.pop(scan_id, None))

    async def execute(self, scan_id: int) -> None:
        """Run a scan inline. Used by tests; production uses start()."""
        self._cancel_events.setdefault(scan_id, asyncio.Event())
        await self._run(scan_id)

    async def wait(self, scan_id: int) -> None:
        task = self._tasks.get(scan_id)
        if task is not None:
            await task

    async def cancel(self, scan_id: int) -> bool:
        event = self._cancel_events.setdefault(scan_id, asyncio.Event())
        event.set()
        async with self.session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return False
            if scan.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
                scan.status = ScanStatus.CANCELLED
                scan.finished_at = utcnow()
                scan.error = "cancelled by user"
                await audit.record(
                    db,
                    "scan.cancelled",
                    user_id=scan.created_by,
                    assessment_id=scan.assessment_id,
                    entity_type="scan",
                    entity_id=scan.id,
                )
                await db.commit()
            return True

    async def recover_interrupted(self) -> int:
        async with self.session_factory() as db:
            result = await db.execute(
                update(Scan)
                .where(Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]))
                .values(
                    status=ScanStatus.FAILED,
                    error="interrupted by restart",
                    finished_at=utcnow(),
                )
            )
            await db.commit()
            count = int(result.rowcount or 0)
        if count:
            logger.warning("Marked %d interrupted scan(s) as failed", count)
        return count

    async def shutdown(self) -> None:
        for event in self._cancel_events.values():
            event.set()
        tasks = [task for task in self._tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run(self, scan_id: int) -> None:
        cancel_event = self._cancel_events.setdefault(scan_id, asyncio.Event())
        try:
            async with self.session_factory() as db:
                scan = await db.get(Scan, scan_id)
                if scan is None or scan.status != ScanStatus.QUEUED:
                    return
                assessment = await db.get(Assessment, scan.assessment_id)
                if assessment is None:
                    await self._finish_failed(scan_id, "assessment no longer exists")
                    return
                rules = list(
                    (
                        await db.execute(
                            select(ScopeItem).where(
                                ScopeItem.assessment_id == assessment.id
                            )
                        )
                    )
                    .scalars()
                    .all()
                )

            if cancel_event.is_set():
                await self._finish_cancelled(scan_id)
                return

            ports = [int(port) for port in (scan.parameters or {}).get("ports", [])]
            guard = ScopeGuard(self.settings)
            decision = await guard.check(
                assessment, rules, scan.target, ScanTool(scan.tool), ports
            )
            if not decision.allowed:
                async with self.session_factory() as db:
                    await audit.record(
                        db,
                        "scan.scope_denied",
                        user_id=scan.created_by,
                        assessment_id=scan.assessment_id,
                        entity_type="scan",
                        entity_id=scan.id,
                        details={"target": scan.target, "reasons": decision.reasons},
                    )
                    await db.commit()
                await self._finish_failed(
                    scan_id,
                    "scope re-check failed: " + "; ".join(decision.reasons),
                )
                return

            await self._mark_running(scan_id, assessment.id)
            if cancel_event.is_set():
                await self._finish_cancelled(scan_id)
                return
            progress = self._progress_callback(scan_id)

            if scan.tool == ScanTool.NMAP:
                async with self._nmap_semaphore:
                    result = await self.nmap_runner.run(
                        profile=NmapProfile(scan.profile),
                        host=scan.target,
                        ports=ports,
                        timeout_seconds=self.settings.scan_timeout(scan.tool, scan.profile),
                        cancel_event=cancel_event,
                    )
                raw = RawOutput(data=result.raw_xml, filename="nmap.xml")
            elif scan.tool == ScanTool.ZAP:
                if self.zap_runner is None:
                    await self._finish_failed(scan_id, "ZAP integration is not available")
                    return
                async with self._zap_lock:
                    await progress(10)
                    raw = await self.zap_runner.run(
                        scan=scan,
                        context_include=decision.context_include,
                        context_exclude=decision.context_exclude,
                        timeout_seconds=self.settings.scan_timeout(scan.tool, scan.profile),
                        cancel_event=cancel_event,
                        progress=progress,
                    )
            elif scan.tool in {
                ScanTool.DIG,
                ScanTool.WHOIS,
                ScanTool.WHATWEB,
                ScanTool.CURL,
            }:
                if self.external_runner is None:
                    await self._finish_failed(
                        scan_id, f"{scan.tool.value} integration is not available"
                    )
                    return
                if scan.tool == ScanTool.WHOIS and _all_private(
                    decision.resolved_ips
                ):
                    whois_skipped = True
                    raw = RawOutput(
                        data=WHOIS_SKIP_NOTE.encode("utf-8"),
                        filename="whois.txt",
                    )
                else:
                    whois_skipped = False
                    async with self._external_semaphore:
                        await progress(10)
                        result = await self.external_runner.run(
                            tool=ScanTool(scan.tool),
                            target=scan.target,
                            timeout_seconds=self.settings.scan_timeout(
                                scan.tool, scan.profile
                            ),
                            cancel_event=cancel_event,
                        )
                    raw = RawOutput(data=result.raw, filename=result.filename)
            else:  # pragma: no cover - model enum prevents this
                await self._finish_failed(scan_id, f"unsupported tool {scan.tool}")
                return

            if cancel_event.is_set():
                await self._finish_cancelled(scan_id)
                return

            relative_path = (
                f"evidence/{scan.assessment_id}/{scan.id}/{raw.filename}"
            )
            await asyncio.to_thread(
                write_data_file, self.settings, relative_path, raw.data
            )
            digest = sha256_bytes(raw.data)

            tool_version = raw.tool_version
            parse_summary: dict[str, Any] | None = None
            parsed: NmapResult | None = None
            document: dict[str, Any] | None = None
            whatweb_entries: list[dict[str, Any]] | None = None
            if scan.tool == ScanTool.NMAP:
                try:
                    parsed = await asyncio.to_thread(parse_nmap_xml, raw.data)
                except NmapParseError as exc:
                    await self._store_raw(scan_id, relative_path, digest)
                    await self._finish_failed(scan_id, f"Nmap XML parse failed: {exc}")
                    return
                tool_version = parsed.nmap_version or tool_version
                parse_summary = {
                    "hosts": len(parsed.hosts),
                    "open_ports": sum(
                        1
                        for host in parsed.hosts
                        for port in host.ports
                        if port.state == "open"
                    ),
                    "elapsed_seconds": parsed.elapsed_seconds,
                }
            elif scan.tool == ScanTool.ZAP:
                try:
                    document = await asyncio.to_thread(parse_zap_document, raw.data)
                except ZapParseError as exc:
                    await self._store_raw(scan_id, relative_path, digest)
                    await self._finish_failed(scan_id, f"ZAP JSON parse failed: {exc}")
                    return
                tool_version = str(document.get("version") or tool_version or "unknown")
                alerts = document.get("alerts") or []
                parse_summary = {
                    "alerts": len(alerts),
                    "high": _risk_count(alerts, "high"),
                    "medium": _risk_count(alerts, "medium"),
                    "low": _risk_count(alerts, "low"),
                    "info": _risk_count(alerts, "info"),
                }
            elif scan.tool in {
                ScanTool.DIG,
                ScanTool.WHOIS,
                ScanTool.WHATWEB,
                ScanTool.CURL,
            }:
                if scan.tool == ScanTool.WHOIS and whois_skipped:
                    parse_summary = {
                        "skipped": True,
                        "note": WHOIS_SKIP_NOTE,
                    }
                else:
                    parse_summary = await asyncio.to_thread(
                        summarize_external_output, ScanTool(scan.tool), raw.data
                    )
                if scan.tool == ScanTool.WHATWEB:
                    try:
                        whatweb_entries = await asyncio.to_thread(
                            parse_whatweb_document, raw.data
                        )
                    except WhatWebParseError as exc:
                        await self._store_raw(scan_id, relative_path, digest)
                        await self._finish_failed(
                            scan_id, f"WhatWeb JSON parse failed: {exc}"
                        )
                        return

            await self._mark_completed(
                scan_id,
                relative_path=relative_path,
                digest=digest,
                tool_version=tool_version,
                parse_summary=parse_summary,
            )
            await self._normalize_findings(
                scan_id,
                parsed=parsed,
                document=document,
                whatweb_entries=whatweb_entries,
            )
            async with self.session_factory() as db:
                fresh = await db.get(Scan, scan_id)
                if fresh is not None:
                    fresh.progress = 100
                    await audit.record(
                        db,
                        "scan.completed",
                        user_id=fresh.created_by,
                        assessment_id=fresh.assessment_id,
                        entity_type="scan",
                        entity_id=fresh.id,
                        details={"tool": fresh.tool, "profile": fresh.profile},
                    )
                    await db.commit()
        except ScanCancelled:
            await self._finish_cancelled(scan_id)
        except ScanTimeout as exc:
            await self._finish_failed(scan_id, str(exc))
        except NmapRunError as exc:
            await self._finish_failed(scan_id, str(exc))
        except ZapError as exc:
            await self._finish_failed(scan_id, str(exc))
        except ExternalToolError as exc:
            await self._finish_failed(scan_id, str(exc))
        except asyncio.CancelledError:
            await self._finish_cancelled(scan_id)
            raise
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            await self._finish_failed(scan_id, f"scan failed: {exc}")

    def _progress_callback(self, scan_id: int) -> ProgressCallback:
        async def report(value: int) -> None:
            await self._update_progress(scan_id, value)

        return report

    async def _update_progress(self, scan_id: int, value: int) -> None:
        clamped = max(0, min(100, int(value)))
        async with self.session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan is not None and scan.status == ScanStatus.RUNNING:
                scan.progress = max(scan.progress, clamped)
                await db.commit()

    async def _mark_running(self, scan_id: int, assessment_id: int) -> None:
        async with self.session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None or scan.status != ScanStatus.QUEUED:
                return
            scan.status = ScanStatus.RUNNING
            scan.started_at = utcnow()
            scan.progress = 2
            assessment = await db.get(Assessment, assessment_id)
            if assessment is not None and assessment.status in {
                AssessmentStatus.DRAFT,
                AssessmentStatus.READY,
            }:
                assessment.status = AssessmentStatus.IN_PROGRESS
            await audit.record(
                db,
                "scan.started",
                user_id=scan.created_by,
                assessment_id=scan.assessment_id,
                entity_type="scan",
                entity_id=scan.id,
                details={"tool": scan.tool, "profile": scan.profile, "target": scan.target},
            )
            await db.commit()

    async def _store_raw(self, scan_id: int, relative_path: str, digest: str) -> None:
        async with self.session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan is not None:
                scan.raw_output_path = relative_path
                scan.raw_output_sha256 = digest
                await db.commit()

    async def _mark_completed(
        self,
        scan_id: int,
        *,
        relative_path: str,
        digest: str,
        tool_version: str | None,
        parse_summary: dict[str, Any] | None,
    ) -> None:
        async with self.session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None or scan.status == ScanStatus.CANCELLED:
                return
            scan.status = ScanStatus.COMPLETED
            scan.progress = 100
            scan.finished_at = utcnow()
            scan.raw_output_path = relative_path
            scan.raw_output_sha256 = digest
            scan.tool_version = tool_version
            parameters = dict(scan.parameters or {})
            if parse_summary is not None:
                parameters["result_summary"] = parse_summary
            parameters["raw_filename"] = relative_path.rsplit("/", 1)[-1]
            scan.parameters = parameters
            await db.commit()

    async def _normalize_findings(
        self,
        scan_id: int,
        *,
        parsed: NmapResult | None,
        document: dict[str, Any] | None,
        whatweb_entries: list[dict[str, Any]] | None,
    ) -> None:
        if parsed is None and document is None and whatweb_entries is None:
            return
        try:
            async with self.session_factory() as db:
                fresh = await db.get(Scan, scan_id)
                if fresh is None or fresh.status != ScanStatus.COMPLETED:
                    return
                if parsed is not None:
                    counts = await normalize_nmap_result(db, fresh, parsed)
                elif whatweb_entries is not None:
                    counts = await normalize_whatweb_result(
                        db, fresh, whatweb_entries
                    )
                else:
                    counts = await normalize_zap_result(db, fresh, document or {})
                await db.commit()
                if counts:
                    logger.info(
                        "%s scan %s upserted %s finding(s)",
                        fresh.tool,
                        scan_id,
                        counts,
                    )
        except Exception:
            logger.exception("Finding normalisation failed for scan %s", scan_id)

    async def _finish_failed(self, scan_id: int, message: str) -> None:
        async with self.session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None or scan.status == ScanStatus.CANCELLED:
                return
            scan.status = ScanStatus.FAILED
            scan.finished_at = utcnow()
            scan.error = message[:2000]
            await audit.record(
                db,
                "scan.failed",
                user_id=scan.created_by,
                assessment_id=scan.assessment_id,
                entity_type="scan",
                entity_id=scan.id,
                details={"error": message[:500]},
            )
            await db.commit()
        logger.warning("Scan %s failed: %s", scan_id, message)

    async def _finish_cancelled(self, scan_id: int) -> None:
        async with self.session_factory() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return
            if scan.status != ScanStatus.CANCELLED:
                scan.status = ScanStatus.CANCELLED
                scan.finished_at = utcnow()
                scan.error = "cancelled by user"
                await db.commit()


_manager: ScanManager | None = None


def get_scan_manager() -> ScanManager:
    global _manager
    if _manager is None:
        from app.db.session import get_session_factory
        from app.services.zap_runner import ZapScanRunner

        settings = get_settings()
        _manager = ScanManager(
            get_session_factory(),
            settings,
            zap_runner=ZapScanRunner(settings),
            external_runner=ExternalToolRunner(settings),
        )
    return _manager


async def shutdown_scan_manager() -> None:
    """Stop jobs and drop the cached manager so a restarted app starts clean."""
    global _manager
    manager = _manager
    _manager = None
    if manager is not None:
        await manager.shutdown()
