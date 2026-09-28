"""Local model through Ollama's chat API."""
import time

import httpx

from ..config import Settings
from .retry import LLMUnavailable, with_retry


def complete(messages: list[dict], *, json_mode: bool, settings: Settings,
             client: httpx.Client | None = None, sleep=time.sleep) -> str:
    body = {"model": settings.ollama_model, "messages": messages, "stream": False,
            "options": {"temperature": 0}}
    if json_mode:
        body["format"] = "json"
    client = client or httpx.Client(timeout=120)
    try:
        resp = with_retry(lambda: client.post(f"{settings.ollama_url}/api/chat", json=body),
                          sleep=sleep)
    except LLMUnavailable as e:
        raise LLMUnavailable(f"{e}. Is Ollama running? Start it with: ollama serve") from e
    return resp.json()["message"]["content"]
