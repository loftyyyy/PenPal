"""Deterministic provider for tests and AI_PROVIDER=mock demos."""

from __future__ import annotations

import json

from app.services.ai.base import AIProvider, ProviderResult


class MockProvider(AIProvider):
    name = "mock"
    model = "mock-deterministic"

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    async def complete_json(
        self, system: str, user: str, *, max_tokens: int
    ) -> ProviderResult:
        self.calls.append(
            {"system": system, "user": user, "max_tokens": str(max_tokens)}
        )
        if "FUNCTION: remediate" in user:
            payload = {
                "summary": "Mock remediation summary for the supplied finding.",
                "steps": [
                    "Reproduce the issue on the authorized test target.",
                    "Apply the vendor-supported fix or configuration change.",
                    "Re-test the affected endpoint and record the evidence.",
                ],
                "code_or_config_example": None,
                "references": ["OWASP Cheat Sheet Series (unverified)"],
                "effort": "medium",
            }
        else:
            payload = {
                "plain_language_explanation": (
                    "Mock interpretation: the tool reported a weakness at the "
                    "supplied endpoint."
                ),
                "why_it_matters": (
                    "Mock impact: an attacker could abuse the weakness if it is "
                    "confirmed by the assessor."
                ),
                "suggested_severity": "medium",
                "severity_rationale": (
                    "Mock rationale: severity is provisional until a human "
                    "assessor verifies the evidence."
                ),
                "likely_false_positive": False,
                "confidence": "medium",
                "owasp_category": None,
                "verification_hints": [
                    "Repeat the request manually against the authorized target.",
                    "Check whether the response still shows the reported weakness.",
                ],
            }
        return ProviderResult(
            content=json.dumps(payload),
            prompt_tokens=0,
            completion_tokens=0,
        )
