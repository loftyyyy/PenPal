"""Fixed-argument runners for dig, whois and WhatWeb."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.core.config import Settings
from app.db.enums import ScanTool
from app.services.nmap_runner import ScanCancelled, ScanTimeout

MAX_EXTERNAL_OUTPUT = 5 * 1024 * 1024
MAX_STDERR = 4000
DIG_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
FILENAMES = {
    ScanTool.DIG: "dig.txt",
    ScanTool.WHOIS: "whois.txt",
    ScanTool.WHATWEB: "whatweb.json",
    ScanTool.CURL: "curl.txt",
}


class ExternalToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExternalRunResult:
    raw: bytes
    filename: str
    argv: list[str]
    return_code: int
    stderr: str = ""


def build_external_argv(
    tool: ScanTool,
    target: str,
    timeout_seconds: int,
    settings: Settings,
    *,
    whatweb_json_path: str | None = None,
) -> list[str]:
    if tool == ScanTool.DIG:
        return [
            settings.dig_binary,
            "+short",
            "+time=5",
            "+tries=1",
            target,
            "A",
        ]
    if tool == ScanTool.WHOIS:
        return [settings.whois_binary, target]
    if tool == ScanTool.WHATWEB:
        argv = [
            settings.whatweb_binary,
            "--no-errors",
            "--color=never",
            "--aggression",
            "1",
            "--follow-redirect=never",
            "--max-threads",
            "1",
            "--open-timeout",
            "10",
            "--read-timeout",
            str(max(5, min(30, timeout_seconds))),
        ]
        if whatweb_json_path:
            argv.append(f"--log-json={whatweb_json_path}")
        argv.append(target)
        return argv
    if tool == ScanTool.CURL:
        return [
            settings.curl_binary,
            "--silent",
            "--show-error",
            "--include",
            "--proto",
            "=http,https",
            "--max-redirs",
            "0",
            "--max-filesize",
            "2000000",
            "--max-time",
            str(max(1, timeout_seconds)),
            "--user-agent",
            "PenPal/0.1",
            target,
        ]
    raise ExternalToolError(f"Unsupported external tool: {tool}")


class ExternalToolRunner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run(
        self,
        *,
        tool: ScanTool,
        target: str,
        timeout_seconds: int,
        cancel_event: asyncio.Event,
    ) -> ExternalRunResult:
        if tool == ScanTool.DIG:
            return await self._run_dig(target, timeout_seconds, cancel_event)
        if tool == ScanTool.WHATWEB:
            return await self._run_whatweb(target, timeout_seconds, cancel_event)
        argv = build_external_argv(tool, target, timeout_seconds, self.settings)
        stdout, stderr, return_code = await self._run_process(
            argv, timeout_seconds, cancel_event, tool
        )
        return ExternalRunResult(
            raw=stdout,
            filename=FILENAMES[tool],
            argv=argv,
            return_code=return_code,
            stderr=stderr,
        )

    async def _run_dig(
        self, target: str, timeout_seconds: int, cancel_event: asyncio.Event
    ) -> ExternalRunResult:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(1, timeout_seconds)
        chunks: list[bytes] = []
        stderr_parts: list[str] = []
        argv: list[str] = []
        return_code = 0
        for record_type in DIG_TYPES:
            remaining = int(max(1, deadline - loop.time()))
            argv = build_external_argv(
                ScanTool.DIG, target, remaining, self.settings
            )
            argv[-1] = record_type
            try:
                stdout, stderr, code = await self._run_process(
                    argv, remaining, cancel_event, ScanTool.DIG
                )
            except ExternalToolError as exc:
                # No record of a type is normal; only binary/startup failures stop.
                if "binary not found" in str(exc) or "could not be started" in str(exc):
                    raise
                stdout, stderr, code = b"", str(exc), 1
            chunks.append(b"; " + record_type.encode("ascii") + b"\n" + stdout)
            if stderr:
                stderr_parts.append(stderr)
            return_code = max(return_code, code)
        raw = b"\n".join(chunks)
        if len(raw) > MAX_EXTERNAL_OUTPUT:
            raise ExternalToolError("dig output exceeded the 5 MB limit")
        return ExternalRunResult(
            raw=raw,
            filename=FILENAMES[ScanTool.DIG],
            argv=argv,
            return_code=return_code,
            stderr=("\n".join(stderr_parts))[:MAX_STDERR],
        )

    async def _run_whatweb(
        self, target: str, timeout_seconds: int, cancel_event: asyncio.Event
    ) -> ExternalRunResult:
        temp_dir = Path(tempfile.mkdtemp(prefix="penpal-whatweb-"))
        json_path = temp_dir / "whatweb.json"
        try:
            argv = build_external_argv(
                ScanTool.WHATWEB,
                target,
                timeout_seconds,
                self.settings,
                whatweb_json_path=str(json_path),
            )
            stdout, stderr, return_code = await self._run_process(
                argv, timeout_seconds, cancel_event, ScanTool.WHATWEB
            )
            raw = json_path.read_bytes() if json_path.is_file() else b""
            if not raw:
                raw = stdout
            if not raw:
                raise ExternalToolError(
                    "whatweb produced no output"
                    + (f": {stderr}" if stderr else "")
                )
            return ExternalRunResult(
                raw=raw,
                filename=FILENAMES[ScanTool.WHATWEB],
                argv=argv,
                return_code=return_code,
                stderr=stderr,
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    async def _run_process(
        self,
        argv: list[str],
        timeout_seconds: int,
        cancel_event: asyncio.Event,
        tool: ScanTool,
    ) -> tuple[bytes, str, int]:
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ExternalToolError(
                f"{tool.value} binary not found in the backend image"
            ) from exc
        except OSError as exc:
            raise ExternalToolError(
                f"{tool.value} could not be started: {exc}"
            ) from exc

        try:
            stdout, stderr = await asyncio.wait_for(
                self._wait_with_cancel(process, cancel_event),
                timeout=max(1, timeout_seconds),
            )
        except TimeoutError as exc:
            await self._terminate(process)
            raise ScanTimeout(
                f"{tool.value} exceeded the {timeout_seconds}s timeout"
            ) from exc
        except ScanCancelled:
            await self._terminate(process)
            raise

        if len(stdout) > MAX_EXTERNAL_OUTPUT:
            raise ExternalToolError(f"{tool.value} output exceeded the 5 MB limit")
        stderr_text = stderr.decode("utf-8", errors="replace")[:MAX_STDERR]
        if not stdout and stderr_text:
            raise ExternalToolError(
                f"{tool.value} produced no output: {stderr_text}"
            )
        return stdout, stderr_text, process.returncode or 0

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


_WHOIS_FIELDS = (
    "Registrar",
    "Creation Date",
    "Registry Expiry Date",
    "Updated Date",
    "Country",
    "Name Server",
)
_WHATWEB_PLUGIN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_.+-]*)\[")
_HTTP_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})")


def _dig_records(text: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(";"):
            name = stripped[1:].strip().upper()
            if name:
                current = name
                records.setdefault(current, [])
            continue
        if not stripped or current is None:
            continue
        records[current].append(stripped)
    return records


def _whatweb_entries(text: str) -> list[dict[str, object]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = data.get("results", [])
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def _whatweb_plugins(entry: dict[str, object]) -> dict[str, list[str]]:
    plugins = entry.get("plugins")
    if not isinstance(plugins, dict):
        return {}
    result: dict[str, list[str]] = {}
    for name, details in plugins.items():
        versions: list[str] = []
        if isinstance(details, dict):
            for key in ("version", "string"):
                values = details.get(key)
                if isinstance(values, list):
                    versions.extend(str(value) for value in values)
                elif isinstance(values, str):
                    versions.append(values)
        elif isinstance(details, list):
            versions.extend(str(value) for value in details)
        result[str(name)] = sorted(set(versions))
    return result


def summarize_external_output(tool: ScanTool, data: bytes) -> dict[str, object]:
    text = data.decode("utf-8", errors="replace")
    if tool == ScanTool.DIG:
        records = _dig_records(text)
        return {
            "records": records,
            "record_count": sum(len(values) for values in records.values()),
        }
    if tool == ScanTool.WHOIS:
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            if key in _WHOIS_FIELDS:
                fields[key] = value.strip()[:500]
        return {"fields": fields, "line_count": len(text.splitlines())}
    if tool == ScanTool.WHATWEB:
        entries = _whatweb_entries(text)
        technologies: dict[str, list[str]] = {}
        status_code: int | None = None
        targets: list[str] = []
        for entry in entries:
            target = entry.get("target")
            if target:
                targets.append(str(target))
            status = entry.get("http_status") or entry.get("status")
            if status_code is None and status is not None:
                try:
                    status_code = int(str(status).split()[0])
                except (ValueError, IndexError):
                    status_code = None
            technologies.update(_whatweb_plugins(entry))
        if not entries:
            plugins = sorted(set(_WHATWEB_PLUGIN_RE.findall(text)))[:50]
            status = re.search(r"\[(\d{3})[^\]]*\]", text)
            return {
                "status_code": int(status.group(1)) if status else None,
                "plugins": plugins,
                "technologies": {},
                "line_count": len(text.splitlines()),
            }
        return {
            "status_code": status_code,
            "targets": targets[:20],
            "technologies": technologies,
            "line_count": len(text.splitlines()),
        }
    if tool == ScanTool.CURL:
        header_bytes, _, body = data.partition(b"\r\n\r\n")
        header_text = header_bytes.decode("utf-8", errors="replace")
        first_line = header_text.splitlines()[0] if header_text.splitlines() else ""
        status_match = _HTTP_STATUS_RE.match(first_line)
        headers: dict[str, str] = {}
        for line in header_text.splitlines()[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()[:500]
        return {
            "status_code": int(status_match.group(1)) if status_match else None,
            "content_type": headers.get("content-type"),
            "header_count": len(headers),
            "body_bytes": len(body),
            "location": headers.get("location"),
        }
    raise ExternalToolError(f"Unsupported external tool: {tool}")
