"""Map raw Nmap and ZAP output into findings with stable fingerprints.

Fingerprints let a re-scan update the same row instead of duplicating it. The
normaliser never touches verification state, final severity, final remediation
or AI suggestions; those belong to the assessor.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import (
    EvidenceType,
    FindingCategory,
    FindingSource,
    Severity,
)
from app.db.models import Evidence, Finding, Scan
from app.services.nmap_parser import NmapPort, NmapResult

logger = logging.getLogger(__name__)

MAX_ZAP_JSON_BYTES = 50 * 1024 * 1024

DATABASE_PORTS = {
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9042: "Cassandra",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}
ADMIN_PORTS = {
    22: "SSH",
    2375: "Docker daemon",
    2376: "Docker daemon (TLS)",
    3389: "Remote Desktop",
    5601: "Kibana",
    5900: "VNC",
    15672: "RabbitMQ management",
}

TAG_CATEGORY: dict[str, FindingCategory] = {
    "sql_injection": FindingCategory.INJECTION,
    "sqli": FindingCategory.INJECTION,
    "xss": FindingCategory.INJECTION,
    "cross_site_scripting": FindingCategory.INJECTION,
    "command_injection": FindingCategory.INJECTION,
    "code_injection": FindingCategory.INJECTION,
    "xxe": FindingCategory.INJECTION,
    "ssrf": FindingCategory.ACCESS_CONTROL,
    "csrf": FindingCategory.ACCESS_CONTROL,
    "access_control": FindingCategory.ACCESS_CONTROL,
    "idor": FindingCategory.ACCESS_CONTROL,
    "authentication": FindingCategory.AUTHENTICATION,
    "session_management": FindingCategory.SESSION_MANAGEMENT,
    "session": FindingCategory.SESSION_MANAGEMENT,
    "cookie": FindingCategory.SESSION_MANAGEMENT,
    "information_disclosure": FindingCategory.INFORMATION_DISCLOSURE,
    "info_disclosure": FindingCategory.INFORMATION_DISCLOSURE,
    "directory_browsing": FindingCategory.EXPOSED_FILES,
    "path_traversal": FindingCategory.EXPOSED_FILES,
    "file_inclusion": FindingCategory.EXPOSED_FILES,
    "transport_security": FindingCategory.SECURITY_CONFIGURATION,
    "https": FindingCategory.SECURITY_CONFIGURATION,
    "headers": FindingCategory.SECURITY_CONFIGURATION,
    "business_logic": FindingCategory.BUSINESS_LOGIC,
}

CWE_CATEGORY: dict[int, FindingCategory] = {
    16: FindingCategory.SECURITY_CONFIGURATION,
    22: FindingCategory.EXPOSED_FILES,
    78: FindingCategory.INJECTION,
    79: FindingCategory.INJECTION,
    89: FindingCategory.INJECTION,
    98: FindingCategory.EXPOSED_FILES,
    200: FindingCategory.INFORMATION_DISCLOSURE,
    209: FindingCategory.INFORMATION_DISCLOSURE,
    269: FindingCategory.ACCESS_CONTROL,
    284: FindingCategory.ACCESS_CONTROL,
    287: FindingCategory.AUTHENTICATION,
    306: FindingCategory.AUTHENTICATION,
    319: FindingCategory.SECURITY_CONFIGURATION,
    326: FindingCategory.SECURITY_CONFIGURATION,
    327: FindingCategory.SECURITY_CONFIGURATION,
    352: FindingCategory.ACCESS_CONTROL,
    384: FindingCategory.SESSION_MANAGEMENT,
    434: FindingCategory.EXPOSED_FILES,
    538: FindingCategory.INFORMATION_DISCLOSURE,
    598: FindingCategory.INFORMATION_DISCLOSURE,
    601: FindingCategory.ACCESS_CONTROL,
    611: FindingCategory.INJECTION,
    613: FindingCategory.SESSION_MANAGEMENT,
    639: FindingCategory.ACCESS_CONTROL,
    693: FindingCategory.SECURITY_CONFIGURATION,
    840: FindingCategory.BUSINESS_LOGIC,
    841: FindingCategory.BUSINESS_LOGIC,
    862: FindingCategory.ACCESS_CONTROL,
    917: FindingCategory.INJECTION,
    918: FindingCategory.ACCESS_CONTROL,
    943: FindingCategory.INJECTION,
    1004: FindingCategory.SESSION_MANAGEMENT,
    1021: FindingCategory.SECURITY_CONFIGURATION,
}

PLUGIN_CATEGORY: dict[int, FindingCategory] = {
    40012: FindingCategory.INJECTION,
    40014: FindingCategory.INJECTION,
    40016: FindingCategory.INJECTION,
    40017: FindingCategory.INJECTION,
    40018: FindingCategory.INJECTION,
    90019: FindingCategory.INJECTION,
    90020: FindingCategory.INJECTION,
    90021: FindingCategory.INJECTION,
    90023: FindingCategory.INJECTION,
    10010: FindingCategory.SESSION_MANAGEMENT,
    10011: FindingCategory.SESSION_MANAGEMENT,
    10020: FindingCategory.SECURITY_CONFIGURATION,
    10021: FindingCategory.SECURITY_CONFIGURATION,
    10023: FindingCategory.INFORMATION_DISCLOSURE,
    10024: FindingCategory.INFORMATION_DISCLOSURE,
    10028: FindingCategory.ACCESS_CONTROL,
    10029: FindingCategory.SESSION_MANAGEMENT,
    10035: FindingCategory.SECURITY_CONFIGURATION,
    10038: FindingCategory.SECURITY_CONFIGURATION,
    10054: FindingCategory.SESSION_MANAGEMENT,
    10096: FindingCategory.INFORMATION_DISCLOSURE,
}

OWASP_BY_CATEGORY: dict[FindingCategory, str] = {
    FindingCategory.INJECTION: "A03:2021 - Injection",
    FindingCategory.AUTHENTICATION: "A07:2021 - Identification and Authentication Failures",
    FindingCategory.SESSION_MANAGEMENT: (
        "A07:2021 - Identification and Authentication Failures"
    ),
    FindingCategory.SECURITY_CONFIGURATION: "A05:2021 - Security Misconfiguration",
    FindingCategory.INFORMATION_DISCLOSURE: "A01:2021 - Broken Access Control",
    FindingCategory.ACCESS_CONTROL: "A01:2021 - Broken Access Control",
    FindingCategory.EXPOSED_FILES: "A01:2021 - Broken Access Control",
    FindingCategory.BUSINESS_LOGIC: "A04:2021 - Insecure Design",
}

OWASP_BY_CWE: dict[int, str] = {
    319: "A02:2021 - Cryptographic Failures",
    326: "A02:2021 - Cryptographic Failures",
    327: "A02:2021 - Cryptographic Failures",
    918: "A10:2021 - Server-Side Request Forgery (SSRF)",
}


class ZapParseError(ValueError):
    pass


def parse_zap_document(data: bytes) -> dict[str, Any]:
    if not data or len(data) > MAX_ZAP_JSON_BYTES:
        raise ZapParseError("ZAP JSON is empty or larger than the 50 MB limit")
    try:
        document = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ZapParseError(f"invalid ZAP JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ZapParseError("ZAP JSON root is not an object")
    alerts = document.get("alerts")
    if alerts is not None and not isinstance(alerts, list):
        raise ZapParseError("ZAP JSON alerts is not a list")
    return document


def normalize_url_for_fingerprint(value: str | None) -> str:
    """Keep scheme, host, non-default port and path; drop query and fragment."""
    text = (value or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return text.split("?", 1)[0].lower()
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return text.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    port = parts.port
    default = 443 if scheme == "https" else 80 if scheme == "http" else None
    port_part = "" if port in (None, default) else f":{port}"
    path = (parts.path or "/").rstrip("/") or "/"
    return f"{scheme}://{host}{port_part}{path}"


def fingerprint(
    source: str,
    rule_id: str,
    method: str | None,
    url: str | None,
    parameter: str | None,
) -> str:
    material = "|".join(
        [
            source,
            str(rule_id),
            (method or "").upper(),
            normalize_url_for_fingerprint(url),
            (parameter or "").strip(),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def severity_from_risk(risk: Any) -> Severity:
    value = str(risk or "").strip().lower()
    if value == "high":
        return Severity.HIGH
    if value == "medium":
        return Severity.MEDIUM
    if value == "low":
        return Severity.LOW
    return Severity.INFO


def _risk_text(severity: Severity) -> str:
    return severity.value


def _as_int(value: Any) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _tags(alert: dict[str, Any]) -> list[str]:
    raw = alert.get("tags")
    if isinstance(raw, list):
        return [str(tag) for tag in raw]
    if isinstance(raw, dict):
        return [str(tag) for tag in raw]
    if isinstance(raw, str) and raw.strip():
        return [part.strip() for part in raw.split(",") if part.strip()]
    return []


def categorize_alert(alert: dict[str, Any]) -> FindingCategory:
    for tag in _tags(alert):
        key = tag.strip().lower().replace("-", "_").replace(" ", "_")
        if key in TAG_CATEGORY:
            return TAG_CATEGORY[key]
    cwe = _as_int(alert.get("cweid"))
    if cwe is not None and cwe in CWE_CATEGORY:
        return CWE_CATEGORY[cwe]
    plugin = _as_int(alert.get("pluginId") or alert.get("pluginid"))
    if plugin is not None and plugin in PLUGIN_CATEGORY:
        return PLUGIN_CATEGORY[plugin]
    text = str(alert.get("alert") or alert.get("name") or "").lower()
    keyword_map = {
        "sql injection": FindingCategory.INJECTION,
        "cross site scripting": FindingCategory.INJECTION,
        "cross-site scripting": FindingCategory.INJECTION,
        "command injection": FindingCategory.INJECTION,
        "directory browsing": FindingCategory.EXPOSED_FILES,
        "path traversal": FindingCategory.EXPOSED_FILES,
        "csrf": FindingCategory.ACCESS_CONTROL,
        "cookie": FindingCategory.SESSION_MANAGEMENT,
        "authentication": FindingCategory.AUTHENTICATION,
        "information disclosure": FindingCategory.INFORMATION_DISCLOSURE,
        "header": FindingCategory.SECURITY_CONFIGURATION,
    }
    for keyword, category in keyword_map.items():
        if keyword in text:
            return category
    return FindingCategory.UNCATEGORIZED


def owasp_category_for(
    category: FindingCategory, alert: dict[str, Any]
) -> str | None:
    cwe = _as_int(alert.get("cweid"))
    if cwe is not None and cwe in OWASP_BY_CWE:
        return OWASP_BY_CWE[cwe]
    return OWASP_BY_CATEGORY.get(category)


async def _upsert_finding(
    db: AsyncSession,
    scan: Scan,
    *,
    source: FindingSource,
    rule_id: str,
    title: str,
    description: str | None,
    category: FindingCategory,
    owasp_category: str | None,
    cwe: str | None,
    affected_url: str | None,
    method: str | None,
    parameter: str | None,
    severity: Severity,
    confidence: str | None,
    raw: dict[str, Any],
) -> tuple[Finding, bool]:
    digest = fingerprint(source.value, rule_id, method, affected_url, parameter)
    existing = await db.scalar(
        select(Finding).where(
            Finding.assessment_id == scan.assessment_id,
            Finding.fingerprint == digest,
        )
    )
    now = utcnow()
    if existing is not None:
        existing.title = title[:500]
        existing.description = description
        existing.category = category
        existing.owasp_category = owasp_category
        existing.cwe = cwe
        existing.affected_url = affected_url[:2048] if affected_url else None
        existing.http_method = method[:20] if method else None
        existing.parameter = parameter[:200] if parameter else None
        existing.tool_severity = severity
        existing.tool_confidence = confidence
        existing.raw = raw
        existing.last_seen_at = now
        if existing.scan_id != scan.id:
            existing.scan_id = scan.id
            existing.seen_count += 1
        return existing, False

    finding = Finding(
        assessment_id=scan.assessment_id,
        scan_id=scan.id,
        source=source,
        fingerprint=digest,
        title=title[:500],
        description=description,
        category=category,
        owasp_category=owasp_category,
        cwe=cwe,
        affected_url=affected_url[:2048] if affected_url else None,
        http_method=method[:20] if method else None,
        parameter=parameter[:200] if parameter else None,
        tool_severity=severity,
        tool_confidence=confidence,
        first_seen_at=now,
        last_seen_at=now,
        seen_count=1,
        raw=raw,
    )
    db.add(finding)
    await db.flush()
    return finding, True


async def _add_http_evidence(
    db: AsyncSession,
    finding: Finding,
    scan: Scan,
    alert: dict[str, Any],
) -> None:
    message = alert.get("httpMessage")
    if not isinstance(message, dict):
        return
    content = "\n".join(
        [
            "REQUEST",
            str(message.get("requestHeader") or ""),
            "",
            str(message.get("requestBody") or ""),
            "",
            "RESPONSE",
            str(message.get("responseHeader") or ""),
            "",
            str(message.get("responseBody") or ""),
        ]
    ).strip()
    if not content or content == "REQUEST\n\n\nRESPONSE":
        return
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    existing = await db.scalar(
        select(Evidence.id).where(
            Evidence.finding_id == finding.id,
            Evidence.type == EvidenceType.HTTP_EXCHANGE,
            Evidence.sha256 == digest,
        )
    )
    if existing is not None:
        return
    db.add(
        Evidence(
            finding_id=finding.id,
            scan_id=scan.id,
            type=EvidenceType.HTTP_EXCHANGE,
            content=content,
            sha256=digest,
            created_by=scan.created_by,
        )
    )


def _service_text(port: NmapPort) -> str:
    service = port.service
    if service is None:
        return ""
    bits = [
        bit
        for bit in (service.name, service.product, service.version, service.extrainfo)
        if bit
    ]
    return " ".join(bits)


async def normalize_nmap_result(
    db: AsyncSession, scan: Scan, parsed: NmapResult
) -> dict[str, int]:
    created = 0
    updated = 0
    for host in parsed.hosts:
        for port in host.ports:
            if port.state != "open":
                continue
            service_text = _service_text(port)
            service_suffix = f" Service: {service_text}." if service_text else ""
            hostnames = f" Hostnames: {', '.join(host.hostnames)}." if host.hostnames else ""
            raw = {
                "host": host.address,
                "hostnames": host.hostnames,
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state,
                "reason": port.reason,
                "service": asdict(port.service) if port.service else None,
            }

            if port.port in DATABASE_PORTS or port.port in ADMIN_PORTS:
                label = DATABASE_PORTS.get(port.port) or ADMIN_PORTS.get(port.port)
                finding, was_created = await _upsert_finding(
                    db,
                    scan,
                    source=FindingSource.NMAP,
                    rule_id=f"exposed-port:{port.protocol}:{port.port}",
                    title=f"{label} service exposed on {port.port}/{port.protocol}",
                    description=(
                        f"Nmap found an open {label} service on {host.address} "
                        f"port {port.port}/{port.protocol}."
                        f"{service_suffix}{hostnames}"
                    ),
                    category=FindingCategory.SECURITY_CONFIGURATION,
                    owasp_category=OWASP_BY_CATEGORY[
                        FindingCategory.SECURITY_CONFIGURATION
                    ],
                    cwe=None,
                    affected_url=f"{host.address}:{port.port}",
                    method=None,
                    parameter=None,
                    severity=Severity.INFO,
                    confidence=port.reason,
                    raw=raw,
                )
                created += int(was_created)
                updated += int(not was_created)

            service = port.service
            if service is not None and (service.product or service.version):
                product = service.product or service.name or "Unknown service"
                version = service.version or "version not reported"
                finding, was_created = await _upsert_finding(
                    db,
                    scan,
                    source=FindingSource.NMAP,
                    rule_id=(
                        f"version:{port.protocol}:{port.port}:"
                        f"{product}:{version}"
                    ),
                    title=f"Service version disclosed on {port.port}/{port.protocol}",
                    description=(
                        f"Nmap identified {product} {version} on {host.address} "
                        f"port {port.port}/{port.protocol}.{hostnames}"
                    ),
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    owasp_category=OWASP_BY_CATEGORY[
                        FindingCategory.INFORMATION_DISCLOSURE
                    ],
                    cwe="CWE-200",
                    affected_url=f"{host.address}:{port.port}",
                    method=None,
                    parameter=None,
                    severity=Severity.INFO,
                    confidence=port.reason,
                    raw=raw,
                )
                created += int(was_created)
                updated += int(not was_created)

    return {"created": created, "updated": updated, "total": created + updated}


async def normalize_zap_result(
    db: AsyncSession, scan: Scan, document: dict[str, Any]
) -> dict[str, int]:
    alerts = document.get("alerts")
    if not isinstance(alerts, list):
        raise ZapParseError("ZAP JSON alerts is not a list")

    created = 0
    updated = 0
    seen: set[str] = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        plugin_id = alert.get("pluginId") or alert.get("pluginid") or ""
        method = alert.get("method")
        url = alert.get("url")
        parameter = alert.get("param")
        digest = fingerprint(FindingSource.ZAP.value, str(plugin_id), method, url, parameter)
        if digest in seen:
            continue
        seen.add(digest)

        severity = severity_from_risk(alert.get("risk"))
        category = categorize_alert(alert)
        cwe_id = _as_int(alert.get("cweid"))
        title = str(alert.get("alert") or alert.get("name") or f"ZAP alert {plugin_id}")
        description = alert.get("description")
        if not description:
            description = (
                f"ZAP reported {title} at {url or 'an unknown URL'} "
                f"with {_risk_text(severity)} risk."
            )
        finding, was_created = await _upsert_finding(
            db,
            scan,
            source=FindingSource.ZAP,
            rule_id=str(plugin_id) or title,
            title=title,
            description=str(description),
            category=category,
            owasp_category=owasp_category_for(category, alert),
            cwe=f"CWE-{cwe_id}" if cwe_id is not None else None,
            affected_url=str(url) if url else None,
            method=str(method) if method else None,
            parameter=str(parameter) if parameter else None,
            severity=severity,
            confidence=str(alert.get("confidence")) if alert.get("confidence") else None,
            raw=alert,
        )
        await _add_http_evidence(db, finding, scan, alert)
        created += int(was_created)
        updated += int(not was_created)

    return {"created": created, "updated": updated, "total": created + updated}
