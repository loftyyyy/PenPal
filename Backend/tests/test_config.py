from __future__ import annotations

import logging

import pytest
from app.core.config import Settings


def _settings(**overrides) -> Settings:
    values = {
        "env": "development",
        "secret_key": "x" * 48,
        "first_admin_password": "long-enough-password",
        "zap_api_key": "real-zap-key",
        "ai_provider": "mock",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_production_refuses_placeholder_secrets() -> None:
    settings = _settings(
        env="production",
        secret_key="CHANGE_ME-dev-only-secret-key",
        first_admin_password="CHANGE_ME-admin-password",
        zap_api_key="CHANGE_ME-zap-api-key",
    )
    with pytest.raises(RuntimeError, match="Unsafe configuration"):
        settings.validate_for_startup()


def test_development_only_warns(caplog: pytest.LogCaptureFixture) -> None:
    settings = _settings(env="development", secret_key="short")
    with caplog.at_level(logging.WARNING):
        settings.validate_for_startup()
    assert "Unsafe configuration" in caplog.text
    assert "allowed because ENV=development" in caplog.text


def test_jwt_algorithm_is_pinned_to_hs256() -> None:
    with pytest.raises(ValueError, match="pinned to HS256"):
        _settings(jwt_algorithm="none")
    assert _settings(jwt_algorithm="hs256").jwt_algorithm == "HS256"


def test_openai_compat_requires_key_and_model() -> None:
    settings = _settings(
        env="production",
        ai_provider="openai_compat",
        ai_base_url="https://example.test/v1",
        ai_model="",
        ai_api_key="",
    )
    with pytest.raises(RuntimeError, match="AI_BASE_URL"):
        settings.validate_for_startup()


def test_fallback_ai_settings_must_be_complete() -> None:
    settings = _settings(
        env="production",
        ai_provider="openai_compat",
        ai_base_url="https://primary.test/v1",
        ai_model="primary-model",
        ai_api_key="primary-key",
        ai_fallback_base_url="https://fallback.test/v1",
    )
    with pytest.raises(RuntimeError, match="AI_FALLBACK_BASE_URL"):
        settings.validate_for_startup()


def test_complete_fallback_ai_settings_are_accepted() -> None:
    settings = _settings(
        ai_provider="openai_compat",
        ai_base_url="https://primary.test/v1",
        ai_model="primary-model",
        ai_api_key="primary-key",
        ai_fallback_base_url="https://fallback.test/v1",
        ai_fallback_model="fallback-model",
        ai_fallback_api_key="fallback-key",
    )
    settings.validate_for_startup()


def test_public_target_warning_is_loud(caplog: pytest.LogCaptureFixture) -> None:
    settings = _settings(
        allow_public_targets=True,
        allowed_public_targets="lsrsv2.ethiodeploy.app",
    )
    with caplog.at_level(logging.WARNING):
        settings.validate_for_startup()
    assert "ALLOW_PUBLIC_TARGETS=true" in caplog.text
    assert "exact hosts in ALLOWED_PUBLIC_TARGETS" in caplog.text
