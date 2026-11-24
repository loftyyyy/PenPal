"""String-backed enums shared by models, schemas and services.

Values are stored in the database, so renaming a member value is a migration.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ASSESSOR = "assessor"


class AssessmentStatus(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    IN_PROGRESS = "in_progress"
    IN_REVIEW = "in_review"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class ScopeKind(StrEnum):
    HOST = "host"
    IP = "ip"
    CIDR = "cidr"
    URL_PREFIX = "url_prefix"
    PORT = "port"


class ScanTool(StrEnum):
    NMAP = "nmap"
    ZAP = "zap"
    DIG = "dig"
    WHOIS = "whois"
    WHATWEB = "whatweb"
    CURL = "curl"


class NmapProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    FULL_TCP = "full_tcp"


class ZapProfile(StrEnum):
    BASELINE = "baseline"
    ACTIVE_LIMITED = "active_limited"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSource(StrEnum):
    NMAP = "nmap"
    ZAP = "zap"
    MANUAL = "manual"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class VerificationStatus(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_RETEST = "needs_retest"


class FindingCategory(StrEnum):
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    SESSION_MANAGEMENT = "session_management"
    SECURITY_CONFIGURATION = "security_configuration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    ACCESS_CONTROL = "access_control"
    EXPOSED_FILES = "exposed_files"
    BUSINESS_LOGIC = "business_logic"
    UNCATEGORIZED = "uncategorized"


class EvidenceType(StrEnum):
    TOOL_OUTPUT = "tool_output"
    HTTP_EXCHANGE = "http_exchange"
    NOTE = "note"
    FILE = "file"


class AIFunction(StrEnum):
    INTERPRET = "interpret"
    REMEDIATE = "remediate"
    SUMMARY = "summary"


class AIAnalysisStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    INVALID_OUTPUT = "invalid_output"


class AIConfidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RemediationEffort(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ReportFormat(StrEnum):
    PDF = "pdf"
    HTML = "html"


class ReportStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"


class VerificationDecision(StrEnum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_RETEST = "needs_retest"


class AuditOutcome(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
