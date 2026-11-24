"""Primary/fallback provider chain with a circuit breaker and attempt records."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from app.services.ai.base import AIProvider, ProviderError, ProviderResult


class FailoverProvider(AIProvider):
    name = "openai_compat+fallback"

    def __init__(
        self,
        primary: AIProvider,
        fallback: AIProvider,
        *,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        clock: Callable[[], float] | None = None,
        fallback_max_tokens: int | None = None,
    ) -> None:
        self.primary = primary
        self.fallback = fallback
        self.model = f"{primary.model} -> {fallback.model}"
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = max(0.0, cooldown_seconds)
        self._clock = clock or time.monotonic
        self._consecutive_failures = 0
        self._open_until = 0.0
        self.fallback_max_tokens = fallback_max_tokens

    @property
    def circuit_open(self) -> bool:
        return self._clock() < self._open_until

    async def complete_json(
        self, system: str, user: str, *, max_tokens: int
    ) -> ProviderResult:
        attempts: list[dict[str, Any]] = []
        primary_error: ProviderError | None = None
        if self.circuit_open:
            attempts.append(
                {
                    "provider": getattr(self.primary, "name", "primary"),
                    "model": getattr(self.primary, "model", None),
                    "outcome": "circuit_open",
                    "latency_ms": 0,
                    "error_class": "circuit_open",
                }
            )
        else:
            started = self._clock()
            try:
                result = await self.primary.complete_json(
                    system, user, max_tokens=max_tokens
                )
            except ProviderError as exc:
                primary_error = exc
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.failure_threshold:
                    self._open_until = self._clock() + self.cooldown_seconds
                attempts.append(
                    {
                        "provider": getattr(self.primary, "name", "primary"),
                        "model": getattr(self.primary, "model", None),
                        "outcome": "error",
                        "latency_ms": int((self._clock() - started) * 1000),
                        "error_class": type(exc).__name__,
                    }
                )
            else:
                self._consecutive_failures = 0
                attempts.append(
                    {
                        "provider": getattr(self.primary, "name", "primary"),
                        "model": getattr(self.primary, "model", None),
                        "outcome": "success",
                        "latency_ms": int((self._clock() - started) * 1000),
                        "error_class": None,
                    }
                )
                return ProviderResult(
                    content=result.content,
                    prompt_tokens=result.prompt_tokens,
                    completion_tokens=result.completion_tokens,
                    provider=result.provider or getattr(self.primary, "name", "primary"),
                    model=result.model or getattr(self.primary, "model", None),
                    attempts=attempts,
                )

        started = self._clock()
        try:
            fallback_tokens = (
                min(max_tokens, self.fallback_max_tokens)
                if self.fallback_max_tokens
                else max_tokens
            )
            result = await self.fallback.complete_json(
                system, user, max_tokens=fallback_tokens
            )
        except ProviderError as fallback_error:
            attempts.append(
                {
                    "provider": getattr(self.fallback, "name", "fallback"),
                    "model": getattr(self.fallback, "model", None),
                    "outcome": "error",
                    "latency_ms": int((self._clock() - started) * 1000),
                    "error_class": type(fallback_error).__name__,
                }
            )
            raise ProviderError(
                "Primary AI provider failed: "
                f"{primary_error or 'circuit open'}; "
                f"fallback also failed: {fallback_error}",
                transient=(
                    bool(primary_error and primary_error.transient)
                    or fallback_error.transient
                ),
                attempts=attempts,
            ) from fallback_error
        attempts.append(
            {
                "provider": getattr(self.fallback, "name", "fallback"),
                "model": getattr(self.fallback, "model", None),
                "outcome": "success",
                "latency_ms": int((self._clock() - started) * 1000),
                "error_class": None,
            }
        )
        return ProviderResult(
            content=result.content,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
            provider=result.provider or getattr(self.fallback, "name", "fallback"),
            model=result.model or getattr(self.fallback, "model", None),
            attempts=attempts,
        )
