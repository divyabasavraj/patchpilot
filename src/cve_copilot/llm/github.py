"""Hosted model through GitHub Models (OpenAI-compatible chat API), used in CI."""
import time

import httpx

from ..config import Settings
from .retry import LLMUnavailable, with_retry


def complete(messages: list[dict], *, json_mode: bool, settings: Settings,
             client: httpx.Client | None = None, sleep=time.sleep) -> str:
    if not settings.github_token:
        raise LLMUnavailable("GITHUB_TOKEN is not set; it is needed for LLM=github")
    body = {"model": settings.github_model, "messages": messages, "temperature": 0}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    headers = {"Authorization": f"Bearer {settings.github_token}"}
    client = client or httpx.Client(timeout=120)
    resp = with_retry(lambda: client.post(settings.github_url, json=body, headers=headers),
                      sleep=sleep)
    return resp.json()["choices"][0]["message"]["content"]
