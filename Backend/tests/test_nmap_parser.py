from __future__ import annotations

import pytest
from app.services.nmap_parser import NmapParseError, parse_nmap_xml
from tests.fakes import NMAP_FIXTURE


def test_parses_fixture_hosts_ports_and_services() -> None:
    result = parse_nmap_xml(NMAP_FIXTURE.read_bytes())

    assert result.nmap_version == "7.95"
    assert result.elapsed_seconds == pytest.approx(12.84)
    assert result.finished == "Sat Nov 22 09:06:53 2026"
    assert len(result.hosts) == 2

    first = result.hosts[0]
    assert first.address == "127.0.0.1"
    assert first.status == "up"
    assert first.hostnames == ["lsrs.local"]
    assert first.os_matches == ["Linux 5.0 - 5.14"]
    ports = {(port.port, port.protocol): port for port in first.ports}
    assert set(ports) == {(22, "tcp"), (80, "tcp"), (3000, "tcp"), (5432, "tcp")}
    assert ports[(80, "tcp")].state == "open"
    assert ports[(80, "tcp")].service is not None
    assert ports[(80, "tcp")].service.product == "nginx"
    assert ports[(80, "tcp")].service.version == "1.24.0"
    assert ports[(5432, "tcp")].state == "closed"

    second = result.hosts[1]
    assert second.address == "127.0.0.2"
    assert second.hostnames == []
    assert second.ports[0].service is not None
    assert second.ports[0].service.name == "redis"


def test_rejects_invalid_xml() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(b"<nmaprun><host></nmaprun>")


def test_rejects_non_nmap_root() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(b"<report><host/></report>")


def test_rejects_empty_input() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(b"")


def test_blocks_entity_expansion() -> None:
    payload = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b'<nmaprun><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>'
    )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(payload)


def test_skips_hosts_without_an_address() -> None:
    result = parse_nmap_xml(
        b'<nmaprun version="7.95"><host><status state="up"/></host>'
        b'<host><address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>'
    )
    assert [host.address for host in result.hosts] == ["127.0.0.1"]
