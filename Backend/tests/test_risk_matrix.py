from __future__ import annotations

import pytest
from app.core.errors import AppError
from app.db.enums import Severity
from app.services.risk_matrix import (
    IMPACT_LABELS,
    LIKELIHOOD_LABELS,
    risk_description,
    severity_for_risk,
)


@pytest.mark.parametrize(
    ("likelihood", "impact", "expected"),
    [
        (1, 1, Severity.INFO),
        (2, 2, Severity.INFO),
        (1, 5, Severity.LOW),
        (2, 4, Severity.LOW),
        (3, 3, Severity.MEDIUM),
        (3, 4, Severity.MEDIUM),
        (4, 4, Severity.HIGH),
        (3, 5, Severity.HIGH),
        (5, 4, Severity.CRITICAL),
        (5, 5, Severity.CRITICAL),
    ],
)
def test_matrix_boundaries(
    likelihood: int, impact: int, expected: Severity
) -> None:
    assert severity_for_risk(likelihood, impact) is expected


@pytest.mark.parametrize("value", [0, 6, -1])
def test_matrix_rejects_out_of_range(value: int) -> None:
    with pytest.raises(AppError, match="between 1 and 5"):
        severity_for_risk(value, 3)


def test_labels_and_description() -> None:
    assert LIKELIHOOD_LABELS[5] == "almost certain"
    assert IMPACT_LABELS[5] == "severe"
    assert risk_description(4, 4) == "likely likelihood x major impact = high"
    assert risk_description(None, 4) is None
