"""Provider interface shared by the mock and OpenAI-compatible providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderResult:
    content: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    provider: str | None = None
    model: str | None = None


class ProviderError(RuntimeError):
    """A provider call failed. The message is safe to persist and log."""

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


class AIProvider(ABC):
    name: str
    model: str

    @abstractmethod
    async def complete_json(
        self, system: str, user: str, *, max_tokens: int
    ) -> ProviderResult:
        """Return the model's raw JSON text."""
        raise NotImplementedError
