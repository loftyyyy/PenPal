from __future__ import annotations

import pytest
from app.db.enums import NmapProfile
from app.services.nmap_runner import NMAP_PROFILE_ARGS, NmapRunError, build_nmap_argv


def test_quick_profile_builds_fixed_argv_with_ports() -> None:
    argv = build_nmap_argv(NmapProfile.QUICK, "127.0.0.1", [80, 443])
    assert argv[0] == "nmap"
    assert argv[1:6] == ["-sT", "-T3", "-F", "-sV", "--version-light"]
    assert argv[argv.index("-p") + 1] == "80,443"
    assert argv[-1] == "127.0.0.1"
    assert "--host-timeout" in argv
    assert argv[argv.index("-oX") + 1] == "-"


def test_profile_argument_sets_are_fixed() -> None:
    assert NMAP_PROFILE_ARGS[NmapProfile.STANDARD] == [
        "-sT",
        "-T3",
        "--top-ports",
        "1000",
        "-sV",
    ]
    assert NMAP_PROFILE_ARGS[NmapProfile.FULL_TCP][:3] == ["-sT", "-T3", "-p-"]


def test_no_port_flag_when_ports_empty() -> None:
    argv = build_nmap_argv(NmapProfile.STANDARD, "127.0.0.1", [])
    assert "-p" not in argv
    assert argv[-1] == "127.0.0.1"


@pytest.mark.parametrize("host", ["", "127.0.0.1 -sV", "host\nname"])
def test_rejects_unsafe_hosts(host: str) -> None:
    with pytest.raises(NmapRunError):
        build_nmap_argv(NmapProfile.QUICK, host, [])


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_rejects_invalid_ports(port: int) -> None:
    with pytest.raises(NmapRunError):
        build_nmap_argv(NmapProfile.QUICK, "127.0.0.1", [port])
