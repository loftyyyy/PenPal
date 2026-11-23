from __future__ import annotations

import json

import httpx
import pytest
from app.core.config import Settings
from app.services.ai.base import ProviderError
from app.services.ai.mock import MockProvider
from app.services.ai.openai_compat import OpenAICompatProvider


def _settings(**overrides) -> Settings:
    values = {
        "ai_provider": "openai_compat",
        "ai_base_url": "https://ai.test/v1",
        "ai_api_key": "test-ai-key",
        "ai_model": "test-model",
        "ai_timeout_seconds": 5,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _provider(handler, **overrides) -> OpenAICompatProvider:
    return OpenAICompatProvider(
        _settings(**overrides),
        transport=httpx.MockTransport(handler),
    )


def _completion(content: str) -> dict:
    return {
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 22},
    }


async def test_request_shape_and_auth_header() -> None:
    seen: list[tuple[str, dict[str, str], dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.url.path,
                dict(request.headers),
                json.loads(request.content),
            )
        )
        return httpx.Response(200, json=_completion('{"answer": 1}'))

    provider = _provider(handler)
    result = await provider.complete_json("system text", "user text", max_tokens=123)

    assert result.content == '{"answer": 1}'
    assert result.prompt_tokens == 11
    assert result.completion_tokens == 22
    assert len(seen) == 1
    path, headers, body = seen[0]
    assert path == "/v1/chat/completions"
    assert headers["authorization"] == "Bearer test-ai-key"
    assert headers["content-type"] == "application/json"
    assert body["model"] == "test-model"
    assert body["messages"] == [
        {"role": "system", "content": "system text"},
        {"role": "user", "content": "user text"},
    ]
    assert body["max_tokens"] == 123
    assert body["temperature"] == 0.2
    assert body["response_format"] == {"type": "json_object"}


async def test_response_format_is_dropped_after_bad_request() -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(400, json={"error": {"message": "unsupported"}})
        return httpx.Response(200, json=_completion("{}"))

    provider = _provider(handler)
    result = await provider.complete_json("system", "user", max_tokens=10)

    assert result.content == "{}"
    assert len(bodies) == 2
    assert "response_format" in bodies[0]
    assert "response_format" not in bodies[1]


async def test_content_parts_are_joined() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": [
                                {"type": "text", "text": "part one "},
                                {"type": "text", "text": "part two"},
                            ]
                        }
                    }
                ]
            },
        )

    provider = _provider(handler)
    result = await provider.complete_json("s", "u", max_tokens=10)
    assert result.content == "part one part two"
    assert result.prompt_tokens is None


@pytest.mark.parametrize(
    ("status", "transient"),
    [(429, True), (500, True), (503, True), (401, False), (403, False)],
)
async def test_http_errors_are_classified(status: int, transient: bool) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": {"message": "nope"}})

    provider = _provider(handler)
    with pytest.raises(ProviderError) as caught:
        await provider.complete_json("s", "u", max_tokens=10)
    assert caught.value.transient is transient
    assert f"HTTP {status}" in str(caught.value)


async def test_transport_timeout_is_transient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    provider = _provider(handler)
    with pytest.raises(ProviderError, match="timed out") as caught:
        await provider.complete_json("s", "u", max_tokens=10)
    assert caught.value.transient is True


async def test_invalid_response_shapes_are_errors() -> None:
    def invalid_json(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    with pytest.raises(ProviderError, match="invalid JSON"):
        await _provider(invalid_json).complete_json("s", "u", max_tokens=10)

    def no_choices(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    with pytest.raises(ProviderError, match="no choices"):
        await _provider(no_choices).complete_json("s", "u", max_tokens=10)

    def wrong_root(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["nope"])

    with pytest.raises(ProviderError, match="unexpected payload"):
        await _provider(wrong_root).complete_json("s", "u", max_tokens=10)


async def test_missing_configuration_fails_without_network() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_completion("{}"))

    with pytest.raises(ProviderError, match="AI_BASE_URL"):
        await _provider(handler, ai_base_url="").complete_json("s", "u", max_tokens=10)
    with pytest.raises(ProviderError, match="AI_API_KEY"):
        await _provider(handler, ai_api_key="").complete_json("s", "u", max_tokens=10)
    assert calls == 0


def test_unknown_provider_is_rejected_by_configuration() -> None:
    with pytest.raises(ValueError, match="AI_PROVIDER"):
        _settings(ai_provider="not-a-provider")


async def test_mock_provider_is_deterministic_and_requests_json() -> None:
    provider = MockProvider()
    interpret = await provider.complete_json(
        "system", "FUNCTION: interpret\n<finding_data>{}</finding_data>", max_tokens=10
    )
    remediate = await provider.complete_json(
        "system", "FUNCTION: remediate\n<finding_data>{}</finding_data>", max_tokens=10
    )
    interpret_payload = json.loads(interpret.content)
    remediate_payload = json.loads(remediate.content)
    assert interpret_payload["suggested_severity"] == "medium"
    assert interpret_payload["confidence"] == "medium"
    assert remediate_payload["effort"] == "medium"
    assert remediate_payload["steps"]
    assert len(provider.calls) == 2
