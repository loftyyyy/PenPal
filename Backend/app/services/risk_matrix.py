"""Likelihood x impact risk matrix.

Both scales are 1..5. The product selects the assessor's final severity band.
The assessor can still override the band explicitly; the API records which
source was used in the audit trail.
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
SEVERITY_BANDS: tuple[tuple[int, Severity], ...] = (
    (4, Severity.INFO),
    (8, Severity.LOW),
    (12, Severity.MEDIUM),
    (19, Severity.HIGH),
    (25, Severity.CRITICAL),
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
    for upper_bound, severity in SEVERITY_BANDS:
        if score <= upper_bound:
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
