"""End-to-end smoke test against a running PenPal stack.

This is NOT a pytest test and makes real HTTP requests to the running backend.
Run it on a Docker host after `docker compose --profile dev-target up --build`.

Example:
    python scripts/smoke_e2e.py --target http://target:3000
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings


class SmokeFailure(RuntimeError):
    pass


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


class Smoke:
    def __init__(self, base_url: str, target: str, timeout: float, client: httpx.Client):
        self.base = base_url.rstrip("/")
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.client = client
        self.headers: dict[str, str] = {}

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        response = self.client.request(
            method, f"{self.base}{path}", headers=self.headers, **kwargs
        )
        return response

    def step(self, label: str, action: Callable[[], object]):
        started = time.perf_counter()
        try:
            result = action()
        except Exception as exc:
            print(f"FAIL {label}: {exc}")
            raise
        print(f"PASS {label} ({(time.perf_counter() - started):.2f}s)")
        return result

    def login(self) -> None:
        settings = get_settings()
        email = os.environ.get("FIRST_ADMIN_EMAIL") or settings.first_admin_email
        password = os.environ.get("FIRST_ADMIN_PASSWORD") or settings.first_admin_password
        if not password:
            raise SmokeFailure("FIRST_ADMIN_PASSWORD is required")
        response = self.client.post(
            f"{self.base}/auth/login",
            json={"email": email, "password": password},
        )
        _check(response.status_code == 200, f"login failed: {response.text}")
        self.headers = {
            "Authorization": f"Bearer {response.json()['access_token']}"
        }

    def create_assessment(self) -> int:
        response = self._request(
            "POST",
            "/assessments",
            json={
                "name": f"PenPal smoke {int(time.time())}",
                "target_name": "LSRS smoke target",
                "target_base_url": self.target,
                "owner_name": "Smoke test owner",
                "authorization_reference": "smoke-test-authorization.pdf",
                "hosting_environment": "Docker Compose",
            },
        )
        _check(response.status_code == 201, response.text)
        return int(response.json()["id"])

    def add_scope(self, assessment_id: int) -> None:
        host = urlsplit(self.target).hostname or self.target
        for payload in (
            {"kind": "host", "value": host, "in_scope": True},
            {"kind": "url_prefix", "value": self.target, "in_scope": True},
        ):
            response = self._request(
                "POST", f"/assessments/{assessment_id}/scope-items", json=payload
            )
            _check(response.status_code == 201, response.text)

    def authorize(self, assessment_id: int) -> None:
        response = self._request(
            "POST",
            f"/assessments/{assessment_id}/confirm-authorization",
            json={"note": "Smoke test authorization"},
        )
        _check(response.status_code == 200, response.text)

    def start_scan(self, assessment_id: int, payload: dict) -> int:
        response = self._request(
            "POST", f"/assessments/{assessment_id}/scans", json=payload
        )
        _check(response.status_code == 202, response.text)
        return int(response.json()["scan_id"])

    def wait_scan(self, scan_id: int) -> dict:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            response = self._request("GET", f"/scans/{scan_id}")
            _check(response.status_code == 200, response.text)
            scan = response.json()
            if scan["status"] in {"completed", "failed", "cancelled"}:
                return scan
            time.sleep(1)
        raise SmokeFailure(f"scan {scan_id} did not finish in {self.timeout}s")

    def list_findings(self, assessment_id: int) -> list[dict]:
        response = self._request(
            "GET", f"/assessments/{assessment_id}/findings?page_size=100"
        )
        _check(response.status_code == 200, response.text)
        return response.json()["items"]

    def analyze_all(self, assessment_id: int) -> None:
        response = self._request(
            "POST",
            f"/assessments/{assessment_id}/analyze",
            json={"only_unanalyzed": True, "force": False},
        )
        _check(response.status_code == 202, response.text)
        job_id = response.json()["job_id"]
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            status = self._request(
                "GET", f"/assessments/{assessment_id}/ai-status"
            ).json()
            job = status.get("job")
            if job and job["id"] == job_id and job["status"] in {
                "completed",
                "failed",
                "cancelled",
            }:
                return
            time.sleep(1)
        raise SmokeFailure("bulk AI job did not finish")

    def verify_some(self, findings: list[dict]) -> None:
        _check(bool(findings), "no findings to verify")
        for finding in findings[:3]:
            response = self._request(
                "PATCH",
                f"/findings/{finding['id']}/verify",
                json={
                    "decision": "confirmed",
                    "likelihood": 4,
                    "impact": 4,
                    "final_remediation": "Smoke test: apply the vendor fix.",
                },
            )
            _check(response.status_code == 200, response.text)

    def summary(self, assessment_id: int) -> None:
        generated = self._request(
            "POST", f"/assessments/{assessment_id}/summary/generate"
        )
        _check(generated.status_code == 200, generated.text)
        summary_id = generated.json()["id"]
        approved = self._request("POST", f"/summaries/{summary_id}/approve")
        _check(approved.status_code == 200, approved.text)

    def report(self, assessment_id: int) -> bytes:
        created = self._request(
            "POST", f"/assessments/{assessment_id}/reports", json={"format": "pdf"}
        )
        _check(created.status_code == 201, created.text)
        report = created.json()
        _check(
            report["format"] == "pdf",
            f"PDF rendering fell back: {report.get('error')}",
        )
        download = self._request("GET", f"/reports/{report['id']}/download")
        _check(download.status_code == 200, download.text)
        content = download.content
        _check(content.startswith(b"%PDF"), "downloaded report is not a PDF")
        _check(len(content) > 100, "downloaded report is empty")
        return content

    def audit(self, assessment_id: int) -> None:
        response = self._request(
            "GET", f"/assessments/{assessment_id}/audit-log?page_size=100"
        )
        _check(response.status_code == 200, response.text)
        actions = {item["action"] for item in response.json()["items"]}
        _check("scope.checked" in actions, "no scope audit events found")
        _check("report.generated" in actions, "no report audit event found")


def main() -> int:
    parser = argparse.ArgumentParser(description="PenPal end-to-end smoke test")
    parser.add_argument("--base-url", default="http://localhost:8000/api/v1")
    parser.add_argument("--target", default="http://target:3000")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument(
        "--ai",
        choices=["mock", "real"],
        default="mock",
        help="Expected server-side AI configuration. The script does not change it.",
    )
    args = parser.parse_args()

    with httpx.Client(timeout=30) as client:
        smoke = Smoke(args.base_url, args.target, args.timeout, client)
        smoke.step("login", smoke.login)
        assessment_id = smoke.step(
            "create assessment", smoke.create_assessment
        )
        smoke.step(
            "add scope", lambda: smoke.add_scope(int(assessment_id))
        )
        smoke.step(
            "authorize", lambda: smoke.authorize(int(assessment_id))
        )
        host = urlsplit(args.target).hostname or args.target
        scans = [
            (
                "nmap quick",
                {
                    "tool": "nmap",
                    "profile": "quick",
                    "target": host,
                    "ports": [urlsplit(args.target).port or 80],
                },
            ),
            (
                "dig",
                {"tool": "dig", "profile": "default", "target": host},
            ),
            (
                "whois",
                {"tool": "whois", "profile": "default", "target": host},
            ),
            (
                "whatweb",
                {"tool": "whatweb", "profile": "default", "target": args.target},
            ),
            (
                "zap baseline",
                {"tool": "zap", "profile": "baseline", "target": args.target + "/"},
            ),
            (
                "http_checks config_baseline",
                {
                    "tool": "http_checks",
                    "profile": "config_baseline",
                    "target": args.target + "/",
                },
            ),
        ]
        for label, payload in scans:
            scan_id = smoke.step(
                f"start {label}",
                lambda payload=payload: smoke.start_scan(int(assessment_id), payload),
            )
            scan = smoke.step(
                f"wait {label}", lambda scan_id=scan_id: smoke.wait_scan(int(scan_id))
            )
            _check(
                scan["status"] == "completed",
                f"{label} finished as {scan['status']}: {scan.get('error')}",
            )
        findings = smoke.step(
            "list findings", lambda: smoke.list_findings(int(assessment_id))
        )
        smoke.step(
            "bulk AI analysis", lambda: smoke.analyze_all(int(assessment_id))
        )
        smoke.step(
            "verify findings", lambda: smoke.verify_some(findings)
        )
        smoke.step("summary + approve", lambda: smoke.summary(int(assessment_id)))
        dashboard = smoke.step(
            "dashboard",
            lambda: smoke._request(
                "GET", f"/assessments/{assessment_id}/dashboard"
            ),
        )
        _check(dashboard.status_code == 200, dashboard.text)
        smoke.step("PDF report + download", lambda: smoke.report(int(assessment_id)))
        smoke.step("audit trail", lambda: smoke.audit(int(assessment_id)))
    print("SMOKE PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SmokeFailure as exc:
        print(f"SMOKE FAIL: {exc}")
        raise SystemExit(1) from exc
