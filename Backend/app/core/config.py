"""Application configuration.

Secrets come from the environment (or a local .env file). Production startup is
refused when any placeholder secret is still in place.
"""

from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_NETWORKS = (
    "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
)
WEAK_SECRET_VALUES = {
    "",
    "changeme",
    "secret",
    "dev",
    "development",
    "test",
    "CHANGE_ME-dev-only-secret-key",
    "CHANGE_ME-admin-password",
    "CHANGE_ME-zap-api-key",
    "dev-insecure-secret-key",
    "admin",
    "password",
}


class Settings(BaseSettings):
    """Typed settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    env: str = "development"
    app_name: str = "PenPal API"
    api_prefix: str = "/api/v1"
    secret_key: str = "CHANGE_ME-dev-only-secret-key"  # noqa: S105
    access_token_expire_minutes: int = 60
    jwt_algorithm: str = "HS256"

    database_url: str = "postgresql+asyncpg://penpal:penpal@db:5432/penpal"
    data_dir: Path = Path("./data")

    first_admin_email: str = "admin@penpal.local"
    first_admin_password: str = "CHANGE_ME-admin-password"  # noqa: S105

    cors_origins: str = "http://localhost:5173"

    zap_base_url: str = "http://zap:8090"
    zap_api_key: str = "CHANGE_ME-zap-api-key"
    zap_timeout_seconds: int = 30
    zap_poll_interval_seconds: float = 2.0
    zap_alert_page_size: int = 200
    zap_max_alerts: int = 1000
    zap_max_message_fetches: int = 100
    zap_message_max_chars: int = 20_000
    zap_active_threads_per_host: int = 1
    zap_active_max_rule_minutes: int = 1
    zap_active_max_scan_minutes: int = 30
    zap_active_max_alerts_per_rule: int = 10

    allowed_target_networks: str = DEFAULT_ALLOWED_NETWORKS
    allow_public_targets: bool = False

    nmap_binary: str = "nmap"
    nmap_max_concurrency: int = 1

    scan_timeout_quick_seconds: int = 600
    scan_timeout_standard_seconds: int = 1800
    scan_timeout_full_tcp_seconds: int = 7200
    scan_timeout_zap_baseline_seconds: int = 1800
    scan_timeout_zap_active_seconds: int = 3600

    ai_provider: str = "mock"
    ai_base_url: str = ""
    ai_api_key: str = ""
    ai_model: str = ""
    ai_max_rpm: int = 10
    ai_max_concurrency: int = 2
    ai_max_evidence_chars: int = 4000
    ai_timeout_seconds: int = 60

    max_upload_bytes: int = 5 * 1024 * 1024
    login_max_attempts: int = 5
    login_lockout_seconds: int = 300

    evidence_text_max_chars: int = 100_000
    report_evidence_max_chars: int = 4000

    @field_validator("env")
    @classmethod
    def _validate_env(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"development", "test", "production"}:
            raise ValueError("ENV must be one of: development, test, production")
        return normalized

    @field_validator("ai_provider")
    @classmethod
    def _validate_ai_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"mock", "openai_compat"}:
            raise ValueError("AI_PROVIDER must be one of: mock, openai_compat")
        return normalized

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def is_test(self) -> bool:
        return self.env == "test"

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def allowed_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in self.allowed_target_networks.split(","):
            value = raw.strip()
            if not value:
                continue
            networks.append(ipaddress.ip_network(value, strict=False))
        if not networks:
            raise ValueError("ALLOWED_TARGET_NETWORKS must contain at least one network")
        return networks

    def validate_for_startup(self) -> None:
        """Refuse unsafe production configuration.

        Development keeps working with placeholders so a teammate can run the
        stack immediately, but a warning is logged.
        """
        problems: list[str] = []
        if self.secret_key.strip() in WEAK_SECRET_VALUES or len(self.secret_key) < 32:
            problems.append("SECRET_KEY is a default or shorter than 32 characters")
        if (
            self.first_admin_password.strip() in WEAK_SECRET_VALUES
            or len(self.first_admin_password) < 12
        ):
            problems.append("FIRST_ADMIN_PASSWORD is a default or shorter than 12 characters")
        if self.zap_api_key.strip() in WEAK_SECRET_VALUES:
            problems.append("ZAP_API_KEY is a default value")
        if self.ai_provider == "openai_compat" and not (
            self.ai_base_url and self.ai_model and self.ai_api_key
        ):
            problems.append(
                "AI_BASE_URL, AI_MODEL and AI_API_KEY are required when "
                "AI_PROVIDER=openai_compat"
            )
        if problems:
            message = "Unsafe configuration: " + "; ".join(problems)
            if self.is_production:
                raise RuntimeError(message)
            logger.warning("%s (allowed because ENV=%s)", message, self.env)

        if self.allow_public_targets:
            logger.warning(
                "SECURITY WARNING: ALLOW_PUBLIC_TARGETS=true. The scope guard will allow "
                "public IP addresses. Only use this on an isolated lab network with written "
                "authorization. This is never acceptable for the PenPal course project."
            )

    def scan_timeout(self, tool: str, profile: str) -> int:
        key = f"scan_timeout_{tool}_{profile}_seconds"
        return int(getattr(self, key, 1800))


@lru_cache
def get_settings() -> Settings:
    return Settings()
