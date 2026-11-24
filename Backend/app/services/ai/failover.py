"""Try a primary provider, then a fallback provider on provider failure."""

from __future__ import annotations

from app.services.ai.base import AIProvider, ProviderError, ProviderResult


class FailoverProvider(AIProvider):
    name = "openai_compat+fallback"

    def __init__(self, primary: AIProvider, fallback: AIProvider) -> None:
        self.primary = primary
        self.fallback = fallback
        self.model = f"{primary.model} -> {fallback.model}"

    async def complete_json(
        self, system: str, user: str, *, max_tokens: int
    ) -> ProviderResult:
        try:
            return await self.primary.complete_json(
                system, user, max_tokens=max_tokens
            )
        except ProviderError as primary_error:
            try:
                return await self.fallback.complete_json(
                    system, user, max_tokens=max_tokens
                )
            except ProviderError as fallback_error:
                raise ProviderError(
                    "Primary AI provider failed: "
                    f"{primary_error}. Fallback failed: {fallback_error}",
                    transient=(primary_error.transient or fallback_error.transient),
                ) from fallback_error
