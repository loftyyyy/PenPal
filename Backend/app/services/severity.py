"""Likelihood x impact severity matrix (project decision).

Both scales are 1..5. The server computes final severity from the assessor's
pair; clients never set final severity directly.
"""

from __future__ import annotations

from app.core.errors import AppError
from app.db.enums import Severity

LIKELIHOOD_LABELS = {
    1: "rare",
    2: "unlikely",
    3: "possible",
    4: "likely",
    5: "almost certain",
}
IMPACT_LABELS = {
    1: "negligible",
    2: "minor",
    3: "moderate",
    4: "major",
    5: "severe",
}
# Inclusive score bands agreed by the team.
SEVERITY_BANDS: tuple[tuple[int, int, Severity], ...] = (
    (1, 2, Severity.INFO),
    (3, 5, Severity.LOW),
    (6, 11, Severity.MEDIUM),
    (12, 19, Severity.HIGH),
    (20, 25, Severity.CRITICAL),
)


def validate_scale(name: str, value: int | None) -> int | None:
    if value is None:
        return None
    if not 1 <= value <= 5:
        raise AppError(
            422,
            "invalid_verification",
            f"{name} must be an integer between 1 and 5",
        )
    return value


def severity_for_risk(likelihood: int, impact: int) -> Severity:
    """Map a validated 1..5 pair to a severity band."""
    if not 1 <= likelihood <= 5 or not 1 <= impact <= 5:
        raise AppError(
            422,
            "invalid_verification",
            "likelihood and impact must be integers between 1 and 5",
        )
    score = likelihood * impact
    for lower, upper, severity in SEVERITY_BANDS:
        if lower <= score <= upper:
            return severity
    return Severity.CRITICAL


def risk_description(likelihood: int | None, impact: int | None) -> str | None:
    if likelihood is None or impact is None:
        return None
    return (
        f"{LIKELIHOOD_LABELS[likelihood]} likelihood x "
        f"{IMPACT_LABELS[impact]} impact = "
        f"{severity_for_risk(likelihood, impact).value}"
    )


def matrix_metadata() -> dict[str, object]:
    return {
        "likelihood": {
            "minimum": 1,
            "maximum": 5,
            "labels": {str(key): value for key, value in LIKELIHOOD_LABELS.items()},
        },
        "impact": {
            "minimum": 1,
            "maximum": 5,
            "labels": {str(key): value for key, value in IMPACT_LABELS.items()},
        },
        "thresholds": [
            {
                "min_score": lower,
                "max_score": upper,
                "severity": severity.value,
            }
            for lower, upper, severity in SEVERITY_BANDS
        ],
        "formula": "score = likelihood x impact",
        "final_severity_source": "server",
    }
