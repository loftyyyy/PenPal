"""Run Nmap with a fixed argument list. Never uses a shell."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

from app.core.config import Settings
from app.db.enums import NmapProfile


class NmapRunError(RuntimeError):
    pass


class ScanCancelled(RuntimeError):
    pass


class ScanTimeout(RuntimeError):
    pass


NMAP_PROFILE_ARGS: dict[NmapProfile, list[str]] = {
    NmapProfile.QUICK: ["-sT", "-T3", "-F", "-sV", "--version-light"],
    NmapProfile.STANDARD: ["-sT", "-T3", "--top-ports", "1000", "-sV"],
    NmapProfile.FULL_TCP: ["-sT", "-T3", "-p-", "-sV"],
}

NMAP_HOST_TIMEOUT: dict[NmapProfile, str] = {
    NmapProfile.QUICK: "120s",
    NmapProfile.STANDARD: "300s",
    NmapProfile.FULL_TCP: "600s",
}


@dataclass
class NmapRunResult:
    raw_xml: bytes
    argv: list[str]
    return_code: int
    stderr: str


def build_nmap_argv(profile: NmapProfile, host: str, ports: list[int]) -> list[str]:
    """Build the argv for a profile. Host and ports are validated by the caller."""
    if not host or any(ch.isspace() for ch in host):
        raise NmapRunError("invalid Nmap host")
    for port in ports:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise NmapRunError("invalid Nmap port")
    argv = [
        "nmap",
        *NMAP_PROFILE_ARGS[profile],
        "--host-timeout",
        NMAP_HOST_TIMEOUT[profile],
        "--max-retries",
        "2",
        "-oX",
        "-",
    ]
    if ports:
        argv.extend(["-p", ",".join(str(port) for port in ports)])
    argv.append(host)
    return argv


class NmapRunner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run(
        self,
        *,
        profile: NmapProfile,
        host: str,
        ports: list[int],
        timeout_seconds: int,
        cancel_event: asyncio.Event,
    ) -> NmapRunResult:
        argv = build_nmap_argv(profile, host, ports)
        # argv[0] is replaced with the configured absolute/name path.
        argv[0] = self.settings.nmap_binary
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise NmapRunError("nmap binary not found in the backend image") from exc
        except OSError as exc:
            raise NmapRunError(f"nmap could not be started: {exc}") from exc

        try:
            stdout, stderr = await asyncio.wait_for(
                self._wait_with_cancel(process, cancel_event),
                timeout=timeout_seconds,
            )
        except TimeoutError as exc:
            await self._terminate(process)
            raise ScanTimeout(f"Nmap exceeded the {timeout_seconds}s timeout") from exc
        except ScanCancelled:
            await self._terminate(process)
            raise

        stderr_text = stderr.decode("utf-8", errors="replace")[:4000]
        if not stdout:
            raise NmapRunError(
                "Nmap produced no output" + (f": {stderr_text}" if stderr_text else "")
            )
        return NmapRunResult(
            raw_xml=stdout,
            argv=argv,
            return_code=process.returncode or 0,
            stderr=stderr_text,
        )

    async def _wait_with_cancel(
        self, process: asyncio.subprocess.Process, cancel_event: asyncio.Event
    ) -> tuple[bytes, bytes]:
        communicate = asyncio.create_task(process.communicate())
        try:
            while True:
                if cancel_event.is_set():
                    communicate.cancel()
                    raise ScanCancelled("scan cancelled")
                done, _ = await asyncio.wait({communicate}, timeout=0.5)
                if done:
                    return communicate.result()
        except asyncio.CancelledError:
            communicate.cancel()
            raise

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(process.wait(), timeout=5)
