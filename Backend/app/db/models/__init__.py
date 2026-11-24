"""All ORM models, imported so metadata is complete for Alembic."""

from app.db.models.ai_analysis import AIAnalysis
from app.db.models.assessment import Assessment, ScopeItem
from app.db.models.audit import AuditLog
from app.db.models.evidence import Evidence
from app.db.models.finding import Finding
from app.db.models.http_checks import HttpCheckConfig, TestAccount
from app.db.models.report import Report
from app.db.models.scan import Scan
from app.db.models.summary import AssessmentSummary
from app.db.models.user import User

__all__ = [
    "AIAnalysis",
    "Assessment",
    "AssessmentSummary",
    "AuditLog",
    "Evidence",
    "Finding",
    "HttpCheckConfig",
    "Report",
    "Scan",
    "ScopeItem",
    "TestAccount",
    "User",
]
