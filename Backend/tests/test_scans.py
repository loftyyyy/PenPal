from __future__ import annotations

import asyncio

from app.db.enums import NmapProfile, ScanStatus, ScanTool, ScopeKind
from app.db.models import AuditLog, Scan, ScopeItem
from app.services.scan_manager import ScanManager
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.fakes import NMAP_FIXTURE, FakeNmapRunner
from tests.utils import add_scope, create_assessment, create_user, login_headers


async def _setup(
    client: AsyncClient,
    db: AsyncSession,
    *,
    email: str = "scan@example.test",
    authorized: bool = True,
    in_scope: bool = True,
    out_of_scope: bool = False,
):
    user = await create_user(db, email=email)
    headers = await login_headers(client, email)
    assessment = await create_assessment(
        db,
        user=user,
        target_base_url="http://127.0.0.1:3000",
        authorized=authorized,
    )
    if in_scope:
        await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    if out_of_scope:
        await add_scope(db, assessment, ScopeKind.CIDR, "127.0.0.0/8", in_scope=False)
    return user, headers, assessment


def _scan_payload(**overrides):
    payload = {
        "tool": "nmap",
        "profile": "quick",
        "target": "127.0.0.1",
        "ports": [80],
    }
    payload.update(overrides)
    return payload


async def test_scan_lifecycle_raw_download_and_audit(
    client: AsyncClient,
    db: AsyncSession,
    scan_manager: ScanManager,
    nmap_runner: FakeNmapRunner,
) -> None:
    _, headers, assessment = await _setup(client, db)

    queued = await client.post(
        f"/api/v1/assessments/{assessment.id}/scans",
        headers=headers,
        json=_scan_payload(),
    )
    assert queued.status_code == 202, queued.text
    body = queued.json()
    assert body["status"] == "queued"
    scan_id = body["scan_id"]

    await scan_manager.wait(scan_id)

    detail = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    scan = detail.json()
    assert scan["status"] == "completed"
    assert scan["progress"] == 100
    assert scan["tool"] == "nmap"
    assert scan["profile"] == "quick"
    assert scan["target"] == "127.0.0.1"
    assert scan["has_raw_output"] is True
    assert len(scan["raw_output_sha256"]) == 64
    assert scan["tool_version"] == "7.95"
    assert scan["duration_seconds"] is not None
    assert scan["parameters"]["ports"] == [80]
    assert scan["parameters"]["result_summary"]["hosts"] == 2
    assert scan["parameters"]["result_summary"]["open_ports"] == 4

    assert len(nmap_runner.calls) == 1
    call = nmap_runner.calls[0]
    assert call["host"] == "127.0.0.1"
    assert call["ports"] == [80]
    assert call["profile"] == NmapProfile.QUICK

    raw = await client.get(f"/api/v1/scans/{scan_id}/raw", headers=headers)
    assert raw.status_code == 200
    assert raw.content == NMAP_FIXTURE.read_bytes()
    assert raw.headers["content-type"].startswith("application/xml")
    assert "attachment" in raw.headers["content-disposition"]

    listed = await client.get(
        f"/api/v1/assessments/{assessment.id}/scans", headers=headers
    )
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["id"] == scan_id

    actions = (
        await db.execute(select(AuditLog.action).where(AuditLog.action.like("scan.%")))
    ).scalars()
    assert {"scan.requested", "scan.started", "scan.completed"} <= set(actions)


async def test_scan_refused_when_authorization_missing(
    client: AsyncClient,
    db: AsyncSession,
    nmap_runner: FakeNmapRunner,
) -> None:
    _, headers, assessment = await _setup(client, db, authorized=False)

    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/scans",
        headers=headers,
        json=_scan_payload(),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "scope_violation"
    assert "authorization" in response.json()["error"]["details"]["reasons"][0]
    assert nmap_runner.calls == []


async def test_scan_refused_out_of_scope_and_default_deny(
    client: AsyncClient,
    db: AsyncSession,
    nmap_runner: FakeNmapRunner,
) -> None:
    _, headers, assessment = await _setup(client, db, out_of_scope=True)

    overridden = await client.post(
        f"/api/v1/assessments/{assessment.id}/scans",
        headers=headers,
        json=_scan_payload(),
    )
    assert overridden.status_code == 403
    reasons = overridden.json()["error"]["details"]["reasons"]
    assert any("out-of-scope" in reason for reason in reasons)

    _, headers2, assessment2 = await _setup(
        client, db, email="unscoped@example.test", in_scope=False
    )
    default_denied = await client.post(
        f"/api/v1/assessments/{assessment2.id}/scans",
        headers=headers2,
        json=_scan_payload(),
    )
    assert default_denied.status_code == 403
    reasons = default_denied.json()["error"]["details"]["reasons"]
    assert any("default deny" in reason for reason in reasons)
    assert nmap_runner.calls == []


async def test_invalid_scan_requests_return_422(
    client: AsyncClient,
    db: AsyncSession,
    nmap_runner: FakeNmapRunner,
) -> None:
    _, headers, assessment = await _setup(client, db)
    base = f"/api/v1/assessments/{assessment.id}/scans"

    bad_profile = await client.post(
        base, headers=headers, json=_scan_payload(profile="baseline")
    )
    assert bad_profile.status_code == 422
    assert bad_profile.json()["error"]["code"] == "invalid_scan_request"

    bad_port = await client.post(
        base, headers=headers, json=_scan_payload(ports=[0])
    )
    assert bad_port.status_code == 422

    bad_target = await client.post(
        base, headers=headers, json=_scan_payload(target="http://")
    )
    assert bad_target.status_code == 422

    zap_host = await client.post(
        base, headers=headers, json=_scan_payload(tool="zap", profile="baseline")
    )
    assert zap_host.status_code == 422

    missing = await client.post(
        "/api/v1/assessments/9999/scans", headers=headers, json=_scan_payload()
    )
    assert missing.status_code == 404
    assert nmap_runner.calls == []


async def test_url_target_uses_host_and_explicit_port(
    client: AsyncClient,
    db: AsyncSession,
    scan_manager: ScanManager,
    nmap_runner: FakeNmapRunner,
) -> None:
    _, headers, assessment = await _setup(client, db)

    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/scans",
        headers=headers,
        json=_scan_payload(target="http://127.0.0.1:3000", ports=[]),
    )
    assert response.status_code == 202, response.text
    await scan_manager.wait(response.json()["scan_id"])

    detail = await client.get(
        f"/api/v1/scans/{response.json()['scan_id']}", headers=headers
    )
    assert detail.json()["target"] == "127.0.0.1"
    assert nmap_runner.calls[0]["ports"] == [3000]


async def test_only_one_active_scan_per_assessment(
    client: AsyncClient,
    db: AsyncSession,
    scan_manager: ScanManager,
    nmap_runner: FakeNmapRunner,
) -> None:
    _, headers, assessment = await _setup(client, db)
    nmap_runner.gate = asyncio.Event()
    base = f"/api/v1/assessments/{assessment.id}/scans"

    first = await client.post(base, headers=headers, json=_scan_payload())
    assert first.status_code == 202
    await asyncio.wait_for(nmap_runner.started.wait(), timeout=5)

    blocked = await client.post(base, headers=headers, json=_scan_payload())
    assert blocked.status_code == 409
    assert "already has a queued or running scan" in blocked.json()["error"]["message"]

    nmap_runner.gate.set()
    await scan_manager.wait(first.json()["scan_id"])

    nmap_runner.gate = None
    second = await client.post(base, headers=headers, json=_scan_payload())
    assert second.status_code == 202
    await scan_manager.wait(second.json()["scan_id"])


async def test_cancel_running_scan(
    client: AsyncClient,
    db: AsyncSession,
    scan_manager: ScanManager,
    nmap_runner: FakeNmapRunner,
) -> None:
    _, headers, assessment = await _setup(client, db)
    nmap_runner.gate = asyncio.Event()

    started = await client.post(
        f"/api/v1/assessments/{assessment.id}/scans",
        headers=headers,
        json=_scan_payload(),
    )
    scan_id = started.json()["scan_id"]
    await asyncio.wait_for(nmap_runner.started.wait(), timeout=5)

    cancelled = await client.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["error"] == "cancelled by user"

    await scan_manager.wait(scan_id)
    detail = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert detail.json()["status"] == "cancelled"

    again = await client.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    assert again.status_code == 409


async def test_restart_recovery_marks_queued_and_running_failed(
    client: AsyncClient,
    db: AsyncSession,
    scan_manager: ScanManager,
) -> None:
    user, _, assessment = await _setup(client, db)
    scans = [
        Scan(
            assessment_id=assessment.id,
            tool=ScanTool.NMAP,
            profile="quick",
            target="127.0.0.1",
            status=status,
            progress=0 if status == ScanStatus.QUEUED else 40,
            parameters={"ports": [80]},
            created_by=user.id,
        )
        for status in (ScanStatus.QUEUED, ScanStatus.RUNNING)
    ]
    db.add_all(scans)
    await db.commit()

    assert await scan_manager.recover_interrupted() == 2
    for scan in scans:
        await db.refresh(scan)
        assert scan.status == ScanStatus.FAILED
        assert scan.error == "interrupted by restart"
        assert scan.finished_at is not None


async def test_execution_time_scope_recheck_uses_current_rules(
    client: AsyncClient,
    db: AsyncSession,
    scan_manager: ScanManager,
    nmap_runner: FakeNmapRunner,
) -> None:
    user, _, assessment = await _setup(client, db)
    scan = Scan(
        assessment_id=assessment.id,
        tool=ScanTool.NMAP,
        profile="quick",
        target="127.0.0.1",
        status=ScanStatus.QUEUED,
        progress=0,
        parameters={"ports": [80]},
        created_by=user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    scope_item = await db.scalar(
        select(ScopeItem).where(ScopeItem.assessment_id == assessment.id)
    )
    assert scope_item is not None
    await db.delete(scope_item)
    await db.commit()

    await scan_manager.execute(scan.id)
    await db.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.error is not None
    assert scan.error.startswith("scope re-check failed")
    assert nmap_runner.calls == []


async def test_raw_download_missing_and_unknown_scan(
    client: AsyncClient,
    db: AsyncSession,
) -> None:
    user, headers, assessment = await _setup(client, db)
    scan = Scan(
        assessment_id=assessment.id,
        tool=ScanTool.NMAP,
        profile="quick",
        target="127.0.0.1",
        status=ScanStatus.QUEUED,
        progress=0,
        parameters={"ports": [80]},
        created_by=user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    unavailable = await client.get(f"/api/v1/scans/{scan.id}/raw", headers=headers)
    assert unavailable.status_code == 409
    assert unavailable.json()["error"]["code"] == "raw_output_unavailable"

    unknown = await client.get("/api/v1/scans/9999", headers=headers)
    assert unknown.status_code == 404


async def test_recon_aggregates_completed_scans(
    client: AsyncClient,
    db: AsyncSession,
    scan_manager: ScanManager,
) -> None:
    _, headers, assessment = await _setup(client, db)
    base = f"/api/v1/assessments/{assessment.id}/scans"
    scan_ids: list[int] = []
    for _ in range(2):
        response = await client.post(base, headers=headers, json=_scan_payload())
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        await scan_manager.wait(scan_id)
        scan_ids.append(scan_id)

    recon = await client.get(
        f"/api/v1/assessments/{assessment.id}/recon", headers=headers
    )
    assert recon.status_code == 200, recon.text
    body = recon.json()
    assert body["totals"] == {
        "scans": 2,
        "hosts": 2,
        "hosts_up": 2,
        "open_ports": 4,
    }
    assert len(body["scans"]) == 2
    assert all(scan["parse_error"] is None for scan in body["scans"])

    hosts = {host["address"]: host for host in body["hosts"]}
    first = hosts["127.0.0.1"]
    assert first["hostnames"] == ["lsrs.local"]
    assert first["scan_ids"] == sorted(scan_ids)
    assert first["os_matches"] == ["Linux 5.0 - 5.14"]
    ports = {port["port"]: port for port in first["ports"]}
    assert ports[80]["state"] == "open"
    assert ports[80]["service"]["product"] == "nginx"
    assert ports[5432]["state"] == "closed"
    assert hosts["127.0.0.2"]["ports"][0]["service"]["name"] == "redis"
