"""Parse Nmap XML into typed reconnaissance data.

The XML comes from a pinned Nmap binary, but it is still untrusted input:
defusedxml blocks entity expansion, and sizes are bounded by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from defusedxml.ElementTree import ParseError as DefusedParseError
from defusedxml.ElementTree import fromstring as defused_fromstring


class NmapParseError(ValueError):
    pass


@dataclass
class NmapService:
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    reason: str | None = None
    service: NmapService | None = None


@dataclass
class NmapHost:
    address: str
    address_type: str
    status: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[NmapPort] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)


@dataclass
class NmapResult:
    hosts: list[NmapHost]
    nmap_version: str | None
    command: str | None
    started: str | None
    finished: str | None
    elapsed_seconds: float | None


def _text(element, path: str, default: str | None = None) -> str | None:
    found = element.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip() or default


def parse_nmap_xml(xml_bytes: bytes) -> NmapResult:
    if not xml_bytes or len(xml_bytes) > 50 * 1024 * 1024:
        raise NmapParseError("Nmap XML is empty or larger than the 50 MB limit")
    try:
        root = defused_fromstring(xml_bytes)
    except (DefusedParseError, ValueError) as exc:
        raise NmapParseError(f"invalid Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapParseError("XML root is not an Nmap run")

    hosts: list[NmapHost] = []
    for host_element in root.findall("host"):
        address_element = host_element.find("address")
        if address_element is None:
            continue
        address = address_element.get("addr", "").strip()
        if not address:
            continue
        status_element = host_element.find("status")
        status = status_element.get("state", "unknown") if status_element is not None else "unknown"
        host = NmapHost(
            address=address,
            address_type=address_element.get("addrtype", "ipv4"),
            status=status,
        )
        hostnames_element = host_element.find("hostnames")
        if hostnames_element is not None:
            for name_element in hostnames_element.findall("hostname"):
                name = name_element.get("name")
                if name:
                    host.hostnames.append(name)

        ports_element = host_element.find("ports")
        if ports_element is not None:
            for port_element in ports_element.findall("port"):
                port_id = port_element.get("portid")
                if port_id is None or not port_id.isdigit():
                    continue
                state_element = port_element.find("state")
                port = NmapPort(
                    port=int(port_id),
                    protocol=port_element.get("protocol", "tcp"),
                    state=state_element.get("state", "unknown")
                    if state_element is not None
                    else "unknown",
                    reason=state_element.get("reason") if state_element is not None else None,
                )
                service_element = port_element.find("service")
                if service_element is not None:
                    port.service = NmapService(
                        name=service_element.get("name"),
                        product=service_element.get("product"),
                        version=service_element.get("version"),
                        extrainfo=service_element.get("extrainfo"),
                        tunnel=service_element.get("tunnel"),
                    )
                host.ports.append(port)

        for osmatch in host_element.findall("os/osmatch"):
            name = osmatch.get("name")
            if name:
                host.os_matches.append(name)
        hosts.append(host)

    runstats = root.find("runstats")
    finished_element = runstats.find("finished") if runstats is not None else None
    elapsed = None
    if finished_element is not None:
        try:
            elapsed = float(finished_element.get("elapsed", ""))
        except ValueError:
            elapsed = None

    return NmapResult(
        hosts=hosts,
        nmap_version=root.get("version"),
        command=root.get("args"),
        started=root.get("startstr"),
        finished=finished_element.get("timestr") if finished_element is not None else None,
        elapsed_seconds=elapsed,
    )
