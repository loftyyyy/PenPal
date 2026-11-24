"""Check the configured primary and fallback AI models against the live API.

Run from Backend/ with .env configured:
    python scripts/check_ai_models.py

Prints status, model, latency and whether the response parsed as a JSON object.
Never prints API keys. Makes real network calls; not part of pytest.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import Settings, get_settings
from app.services.ai.openai_compat import OpenAICompatProvider

PROMPT = (
    'Return only one JSON object with exactly this field: '
    '{"ok": true}. Do not add prose.'
)


async def check(label: str, settings: Settings) -> bool:
    provider = OpenAICompatProvider(settings)
    started = time.perf_counter()
    try:
        result = await provider.complete_json(
            "You return JSON only.", PROMPT, max_tokens=settings.ai_max_tokens
        )
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000
        print(f"{label}: FAIL {type(exc).__name__}: {exc} ({elapsed:.0f} ms)")
        return False
    elapsed = (time.perf_counter() - started) * 1000
    text = result.content.strip()
    start = text.find("{")
    end = text.rfind("}")
    parsed = False
    if start >= 0 and end > start:
        try:
            payload = json.loads(text[start : end + 1])
            parsed = isinstance(payload, dict)
        except ValueError:
            parsed = False
    print(
        f"{label}: {'OK' if parsed else 'BAD_JSON'} model={result.model} "
        f"provider={result.provider} latency={elapsed:.0f}ms chars={len(text)}"
    )
    return parsed


async def main() -> int:
    settings = get_settings()
    if settings.ai_provider != "openai_compat":
        print("AI_PROVIDER is not openai_compat; set it to test a live chain.")
        return 1
    ok_primary = await check("primary", settings)
    fallback = settings.model_copy(
        update={
            "ai_base_url": settings.ai_fallback_base_url,
            "ai_api_key": settings.ai_fallback_api_key,
            "ai_model": settings.ai_fallback_model,
            "ai_extra_body": settings.ai_fallback_extra_body,
            "ai_max_tokens": settings.ai_fallback_max_tokens,
            "ai_timeout_seconds": settings.ai_fallback_timeout_seconds,
        }
    )
    ok_fallback = False
    if settings.ai_fallback_base_url and settings.ai_fallback_model:
        ok_fallback = await check("fallback", fallback)
    else:
        print("fallback: SKIPPED (not configured)")
    return 0 if (ok_primary or ok_fallback) else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
