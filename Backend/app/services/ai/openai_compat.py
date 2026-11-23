"""OpenAI-compatible chat completions provider.

One implementation covers Gemini's compatibility endpoint, Groq, OpenRouter and
a local Ollama server; only ``AI_BASE_URL``, ``AI_API_KEY`` and ``AI_MODEL``
change.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.core.config import Settings
from app.services.ai.base import AIProvider, ProviderError, ProviderResult


class OpenAICompatProvider(AIProvider):
    name = "openai_compat"

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.model = settings.ai_model or "unconfigured"
        self._transport = transport
        self._endpoint = (
            f"{settings.ai_base_url.rstrip('/')}/chat/completions"
            if settings.ai_base_url
            else ""
        )

    async def complete_json(
        self, system: str, user: str, *, max_tokens: int
    ) -> ProviderResult:
        if not self._endpoint or not self.settings.ai_model:
            raise ProviderError(
                "AI_BASE_URL and AI_MODEL must be configured for the OpenAI-compatible "
                "provider"
            )
        if not self.settings.ai_api_key:
            raise ProviderError("AI_API_KEY is not configured")

        headers = {
            "Authorization": f"Bearer {self.settings.ai_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "PenPal/0.1",
        }
        timeout = httpx.Timeout(float(self.settings.ai_timeout_seconds))
        async with httpx.AsyncClient(
            timeout=timeout, transport=self._transport
        ) as client:
            try:
                response = await client.post(
                    self._endpoint,
                    headers=headers,
                    json=self._body(system, user, max_tokens, json_mode=True),
                )
                if response.status_code in {400, 422}:
                    # Some gateways reject response_format; retry once without it.
                    response = await client.post(
                        self._endpoint,
                        headers=headers,
                        json=self._body(system, user, max_tokens, json_mode=False),
                    )
            except httpx.TimeoutException as exc:
                raise ProviderError("AI request timed out", transient=True) from exc
            except httpx.TransportError as exc:
                raise ProviderError(
                    "AI provider could not be reached", transient=True
                ) from exc

        if response.status_code == 429 or response.status_code >= 500:
            raise ProviderError(
                f"AI provider returned HTTP {response.status_code}", transient=True
            )
        if response.status_code >= 400:
            raise ProviderError(f"AI provider returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("AI provider returned invalid JSON") from exc
        return self._result(data)

    def _body(
        self, system: str, user: str, max_tokens: int, *, json_mode: bool
    ) -> dict[str, Any]:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    @staticmethod
    def _result(data: Any) -> ProviderResult:
        if not isinstance(data, dict):
            raise ProviderError("AI provider returned an unexpected payload")
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderError("AI provider returned no choices")
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, list):
            content = "".join(
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            )
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return ProviderResult(
            content=content if isinstance(content, str) else "",
            prompt_tokens=_token_count(usage.get("prompt_tokens")),
            completion_tokens=_token_count(usage.get("completion_tokens")),
        )


def _token_count(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
