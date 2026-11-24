"""Aggregate Nmap reconnaissance from completed scans."""

from __future__ import annotations

import asyncio
import ipaddress

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.base import utcnow
from app.db.enums import ScanStatus, ScanTool
from app.db.models import Assessment, Scan
from app.schemas.recon import (
    ReconDNSOut,
    ReconHostOut,
    ReconHTTPOut,
    ReconOut,
    ReconPortOut,
    ReconScanOut,
    ReconServiceOut,
    ReconTechnologyOut,
    ReconTotalsOut,
    ReconWhoisOut,
)
from app.services.nmap_parser import NmapHost, NmapParseError, NmapPort, parse_nmap_xml
from app.services.storage import UnsafePathError, read_data_file

MAX_RECON_XML_BYTES = 50 * 1024 * 1024


def _service_out(port: NmapPort) -> ReconServiceOut | None:
    if port.service is None:
        return None
    service = port.service
    if not any(
        (service.name, service.product, service.version, service.extrainfo, service.tunnel)
    ):
        return None
    return ReconServiceOut(
        name=service.name,
        product=service.product,
        version=service.version,
        extrainfo=service.extrainfo,
        tunnel=service.tunnel,
    )


def _port_out(port: NmapPort) -> ReconPortOut:
    return ReconPortOut(
        port=port.port,
        protocol=port.protocol,
        state=port.state,
        reason=port.reason,
        service=_service_out(port),
    )


def _sort_address(address: str) -> tuple[int, int, str]:
    try:
        ip = ipaddress.ip_address(address)
        return (ip.version, int(ip), address)
    except ValueError:
        return (99, 0, address)


def _merge_host(
    hosts: dict[str, ReconHostOut], host: NmapHost, scan_id: int
) -> None:
    existing = hosts.get(host.address)
    if existing is None:
        existing = ReconHostOut(
            address=host.address,
            address_type=host.address_type,
            status=host.status,
            hostnames=[],
            os_matches=[],
            ports=[],
            scan_ids=[],
        )
        hosts[host.address] = existing
    if host.status == "up":
        existing.status = "up"
    for name in host.hostnames:
        if name not in existing.hostnames:
            existing.hostnames.append(name)
    for name in host.os_matches:
        if name not in existing.os_matches:
            existing.os_matches.append(name)
    if scan_id not in existing.scan_ids:
        existing.scan_ids.append(scan_id)

    index = {(port.port, port.protocol): port for port in existing.ports}
    for port in host.ports:
        key = (port.port, port.protocol)
        previous = index.get(key)
        candidate = _port_out(port)
        if previous is None:
            existing.ports.append(candidate)
            index[key] = candidate
            continue
        # Prefer an open observation over a closed/filtered one, and fill in
        # service detail discovered by a later profile.
        if previous.state != "open" and candidate.state == "open":
            previous.state = candidate.state
            previous.reason = candidate.reason
        if previous.service is None and candidate.service is not None:
            previous.service = candidate.service


async def build_recon(
    db: AsyncSession, settings: Settings, assessment: Assessment
) -> ReconOut:
    result = await db.execute(
        select(Scan)
        .where(
            Scan.assessment_id == assessment.id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.id)
    )
    scans = result.scalars().all()

    hosts: dict[str, ReconHostOut] = {}
    scan_rows: list[ReconScanOut] = []
    dns_rows: list[ReconDNSOut] = []
    whois_rows: list[ReconWhoisOut] = []
    technology_rows: list[ReconTechnologyOut] = []
    http_rows: list[ReconHTTPOut] = []
    for scan in scans:
        parse_error: str | None = None
        summary = (scan.parameters or {}).get("result_summary") or {}
        if scan.tool == ScanTool.NMAP:
            if scan.raw_output_path:
                try:
                    data = await asyncio.to_thread(
                        read_data_file,
                        settings,
                        scan.raw_output_path,
                        MAX_RECON_XML_BYTES,
                    )
                    parsed = await asyncio.to_thread(parse_nmap_xml, data)
                except (UnsafePathError, OSError, NmapParseError) as exc:
                    parse_error = str(exc)
                else:
                    for host in parsed.hosts:
                        _merge_host(hosts, host, scan.id)
            else:
                parse_error = "raw Nmap XML was not stored"
        elif scan.tool == ScanTool.DIG:
            dns_rows.append(
                ReconDNSOut(
                    scan_id=scan.id,
                    target=scan.target,
                    records=summary.get("records", {}),
                    record_count=int(summary.get("record_count", 0)),
                )
            )
        elif scan.tool == ScanTool.WHOIS:
            whois_rows.append(
                ReconWhoisOut(
                    scan_id=scan.id,
                    target=scan.target,
                    skipped=bool(summary.get("skipped", False)),
                    note=summary.get("note"),
                    fields=summary.get("fields", {}),
                )
            )
        elif scan.tool == ScanTool.WHATWEB:
            technology_rows.append(
                ReconTechnologyOut(
                    scan_id=scan.id,
                    target=scan.target,
                    status_code=summary.get("status_code"),
                    targets=summary.get("targets", []),
                    technologies=summary.get("technologies", {}),
                )
            )
        elif scan.tool == ScanTool.CURL:
            http_rows.append(
                ReconHTTPOut(
                    scan_id=scan.id,
                    target=scan.target,
                    status_code=summary.get("status_code"),
                    content_type=summary.get("content_type"),
                    header_count=int(summary.get("header_count", 0)),
                    body_bytes=int(summary.get("body_bytes", 0)),
                    location=summary.get("location"),
                )
            )

        scan_rows.append(
            ReconScanOut(
                id=scan.id,
                profile=scan.profile,
                target=scan.target,
                status=scan.status.value,
                progress=scan.progress,
                started_at=scan.started_at,
                finished_at=scan.finished_at,
                duration_seconds=scan.duration_seconds,
                tool_version=scan.tool_version,
                raw_output_sha256=scan.raw_output_sha256,
                error=scan.error,
                parse_error=parse_error,
            )
        )

    host_rows = sorted(hosts.values(), key=lambda item: _sort_address(item.address))
    for host_row in host_rows:
        host_row.ports.sort(key=lambda port: (port.port, port.protocol))
        host_row.scan_ids.sort()

    open_ports = sum(
        1
        for host_row in host_rows
        for port in host_row.ports
        if port.state == "open"
    )
    return ReconOut(
        assessment_id=assessment.id,
        generated_at=utcnow(),
        totals=ReconTotalsOut(
            scans=len(scan_rows),
            hosts=len(host_rows),
            hosts_up=sum(1 for host_row in host_rows if host_row.status == "up"),
            open_ports=open_ports,
        ),
        scans=scan_rows,
        hosts=host_rows,
        dns=dns_rows,
        whois=whois_rows,
        technologies=technology_rows,
        http=http_rows,
    )
