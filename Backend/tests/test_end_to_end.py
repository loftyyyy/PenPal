from __future__ import annotations

from app.services.ai.manager import AIAnalysisManager
from app.services.scan_manager import ScanManager
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.fakes import FakeNmapRunner, FakeZapRunner
from tests.utils import create_user, login_headers


async def test_full_assessment_flow_with_mock_tools_and_ai(
    client: AsyncClient,
    db: AsyncSession,
    scan_manager: ScanManager,
    ai_manager: AIAnalysisManager,
    nmap_runner: FakeNmapRunner,
    zap_runner: FakeZapRunner,
) -> None:
    await create_user(db, email="flow@example.test")
    headers = await login_headers(client, "flow@example.test")

    created = await client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "End-to-end flow",
            "target_name": "LSRS demo",
            "target_base_url": "http://127.0.0.1:3000",
            "owner_name": "Demo owner",
            "authorization_reference": "signed-authorization.pdf",
            "selected_categories": ["injection", "security_configuration"],
        },
    )
    assert created.status_code == 201, created.text
    assessment_id = created.json()["id"]
    assert created.json()["authorization_confirmed"] is False

    scope = await client.post(
        f"/api/v1/assessments/{assessment_id}/scope-items",
        headers=headers,
        json={"kind": "host", "value": "127.0.0.1"},
    )
    assert scope.status_code == 201, scope.text

    confirmed = await client.post(
        f"/api/v1/assessments/{assessment_id}/confirm-authorization",
        headers=headers,
        json={"note": "Authorization letter checked."},
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["authorization_confirmed"] is True

    nmap = await client.post(
        f"/api/v1/assessments/{assessment_id}/scans",
        headers=headers,
        json={
            "tool": "nmap",
            "profile": "quick",
            "target": "127.0.0.1",
            "ports": [80],
        },
    )
    assert nmap.status_code == 202, nmap.text
    await scan_manager.wait(nmap.json()["scan_id"])
    nmap_detail = await client.get(
        f"/api/v1/scans/{nmap.json()['scan_id']}", headers=headers
    )
    assert nmap_detail.json()["status"] == "completed"
    assert len(nmap_runner.calls) == 1

    zap = await client.post(
        f"/api/v1/assessments/{assessment_id}/scans",
        headers=headers,
        json={
            "tool": "zap",
            "profile": "baseline",
            "target": "http://127.0.0.1:3000/",
        },
    )
    assert zap.status_code == 202, zap.text
    await scan_manager.wait(zap.json()["scan_id"])
    zap_detail = await client.get(
        f"/api/v1/scans/{zap.json()['scan_id']}", headers=headers
    )
    assert zap_detail.json()["status"] == "completed"
    assert len(zap_runner.calls) == 1

    findings = await client.get(
        f"/api/v1/assessments/{assessment_id}/findings",
        headers=headers,
        params={"page_size": 100},
    )
    assert findings.status_code == 200
    finding_rows = findings.json()["items"]
    assert findings.json()["total"] == 10
    sqli = next(
        item for item in finding_rows if item["title"] == "SQL Injection"
    )

    evidence = await client.post(
        f"/api/v1/findings/{sqli['id']}/evidence",
        headers=headers,
        data={"note": "Manually reproduced the SQL error in the search field."},
    )
    assert evidence.status_code == 201

    bulk = await client.post(
        f"/api/v1/assessments/{assessment_id}/analyze",
        headers=headers,
        json={"only_unanalyzed": True},
    )
    assert bulk.status_code == 202, bulk.text
    await ai_manager.wait(bulk.json()["job_id"])
    ai_status = await client.get(
        f"/api/v1/assessments/{assessment_id}/ai-status", headers=headers
    )
    assert ai_status.json()["findings_with_interpretation"] == 10
    assert ai_status.json()["pending_findings"] == 0

    verified = await client.patch(
        f"/api/v1/findings/{sqli['id']}/verify",
        headers=headers,
        json={
            "decision": "confirmed",
            "likelihood": 5,
            "impact": 5,
            "final_remediation": "Use parameterised queries.",
        },
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["verification_status"] == "confirmed"
    assert verified.json()["final_severity"] == "critical"

    dashboard = await client.get(
        f"/api/v1/assessments/{assessment_id}/dashboard", headers=headers
    )
    assert dashboard.status_code == 200
    dashboard_body = dashboard.json()
    assert dashboard_body["total_findings"] == 10
    assert dashboard_body["status_counts"]["confirmed"] == 1
    assert dashboard_body["status_counts"]["pending"] == 9
    assert dashboard_body["severity_confirmed"]["critical"] == 1
    assert dashboard_body["ai_coverage"]["analyzed"] == 10
    assert dashboard_body["top_confirmed_findings"][0]["id"] == sqli["id"]

    report = await client.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        headers=headers,
        json={"format": "html"},
    )
    assert report.status_code == 201, report.text
    report_body = report.json()
    assert report_body["status"] == "ready"
    assert report_body["summary_counts"]["confirmed"] == 1
    assert report_body["summary_counts"]["critical"] == 1

    download = await client.get(
        f"/api/v1/reports/{report_body['id']}/download", headers=headers
    )
    assert download.status_code == 200
    html = download.text
    assert "SQL Injection" in html
    assert "Manually reproduced the SQL error" in html
    assert "UNVERIFIED: Missing Anti-clickjacking Header" in html

    audit = await client.get(
        f"/api/v1/assessments/{assessment_id}/audit-log",
        headers=headers,
        params={"page_size": 100},
    )
    actions = {item["action"] for item in audit.json()["items"]}
    assert {
        "assessment.created",
        "scope.item_added",
        "assessment.authorization_confirmed",
        "scan.requested",
        "scan.completed",
        "ai.bulk_requested",
        "ai.analyzed",
        "evidence.added",
        "finding.verified",
        "report.generated",
    } <= actions
