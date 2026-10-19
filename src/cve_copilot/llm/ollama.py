"""Local model through Ollama's chat API."""
import time

import httpx

from ..config import Settings
from .retry import LLMUnavailable, with_retry

# Ollama's default window (4,096 tokens) is shared by prompt and answer; a scan prompt alone
# can reach ~3,200, and anything past the window is silently cut. 8,192 fits a 16 GB Mac.
CONTEXT_TOKENS = 8192
# A good answer is ~300 tokens. At temperature 0 a draft can repeat the same IDs forever, and
# without a cap it runs into the 120 s timeout three times before the user sees anything.
MAX_ANSWER_TOKENS = 1024


def complete(messages: list[dict], *, json_mode: bool, settings: Settings,
             client: httpx.Client | None = None, sleep=time.sleep) -> str:
    body = {"model": settings.ollama_model, "messages": messages, "stream": False,
            "options": {"temperature": 0, "num_ctx": CONTEXT_TOKENS,
                        "num_predict": MAX_ANSWER_TOKENS}}
    if json_mode:
        body["format"] = "json"
    client = client or httpx.Client(timeout=120)
    try:
        resp = with_retry(lambda: client.post(f"{settings.ollama_url}/api/chat", json=body),
                          sleep=sleep)
    except LLMUnavailable as e:
        raise LLMUnavailable(f"{e}. Is Ollama running? Start it with: ollama serve") from e
    return resp.json()["message"]["content"]
