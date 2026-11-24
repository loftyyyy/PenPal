"""In-process bulk AI analysis jobs.

The course deployment runs one backend process. Progress lives in memory and is
reported by the assessment AI-status endpoint; individual results live in
``ai_analyses``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.errors import ConflictError
from app.db.base import utcnow
from app.db.models import Finding
from app.services.ai.service import AIAnalysisService, get_ai_service

logger = logging.getLogger(__name__)


class AIJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AIJob:
    id: int
    assessment_id: int
    requested_by: int
    total: int
    finding_ids: list[int] = field(default_factory=list, repr=False)
    force: bool = False
    status: AIJobStatus = AIJobStatus.QUEUED
    processed: int = 0
    failed: int = 0
    error: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None


class AIAnalysisManager:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        service: AIAnalysisService | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.service = service or get_ai_service(settings)
        self._jobs: dict[int, AIJob] = {}
        self._tasks: dict[int, asyncio.Task[None]] = {}
        self._next_id = 1

    async def start_bulk(
        self,
        *,
        assessment_id: int,
        requested_by: int,
        finding_ids: list[int],
        force: bool = False,
    ) -> AIJob:
        for job in self._jobs.values():
            if job.assessment_id == assessment_id and job.status in {
                AIJobStatus.QUEUED,
                AIJobStatus.RUNNING,
            }:
                raise ConflictError(
                    "This assessment already has a running bulk analysis job"
                )
        job = AIJob(
            id=self._next_id,
            assessment_id=assessment_id,
            requested_by=requested_by,
            total=len(finding_ids),
            finding_ids=list(finding_ids),
            force=force,
        )
        self._next_id += 1
        self._jobs[job.id] = job
        task = asyncio.create_task(self._run(job), name=f"ai-job-{job.id}")
        self._tasks[job.id] = task
        task.add_done_callback(lambda _task: self._tasks.pop(job.id, None))
        return job

    async def wait(self, job_id: int) -> None:
        task = self._tasks.get(job_id)
        if task is not None:
            await task

    def get(self, job_id: int) -> AIJob | None:
        return self._jobs.get(job_id)

    def latest_for_assessment(self, assessment_id: int) -> AIJob | None:
        candidates = [
            job for job in self._jobs.values() if job.assessment_id == assessment_id
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda job: job.id)

    async def _run(self, job: AIJob) -> None:
        job.status = AIJobStatus.RUNNING
        job.started_at = utcnow()
        try:
            for finding_id in job.finding_ids:
                try:
                    async with self.session_factory() as db:
                        finding = await db.get(Finding, finding_id)
                        if finding is None:
                            job.failed += 1
                        else:
                            await self.service.analyze_finding(
                                db,
                                finding,
                                user_id=job.requested_by,
                                force=job.force,
                            )
                            await db.commit()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    job.failed += 1
                    logger.exception(
                        "Bulk AI analysis failed for finding %s", finding_id
                    )
                finally:
                    job.processed += 1
            if job.total and job.failed == job.total:
                job.status = AIJobStatus.FAILED
                job.error = f"AI analysis failed for all {job.total} finding(s)"
            else:
                job.status = AIJobStatus.COMPLETED
        except asyncio.CancelledError:
            job.status = AIJobStatus.CANCELLED
            job.error = "cancelled by shutdown"
            raise
        finally:
            job.finished_at = utcnow()

    async def shutdown(self) -> None:
        tasks = [task for task in self._tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


_manager: AIAnalysisManager | None = None


def get_ai_manager() -> AIAnalysisManager:
    global _manager
    if _manager is None:
        from app.db.session import get_session_factory

        settings = get_settings()
        _manager = AIAnalysisManager(get_session_factory(), settings)
    return _manager


async def shutdown_ai_manager() -> None:
    global _manager
    manager = _manager
    _manager = None
    if manager is not None:
        await manager.shutdown()
