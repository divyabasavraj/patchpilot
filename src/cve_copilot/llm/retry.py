"""Retry HTTP calls on network errors and rate limits."""
import time
from collections.abc import Callable

import httpx

RETRY_STATUS = {429, 500, 502, 503, 504}


class LLMUnavailable(RuntimeError):
    """The model could not be reached (infrastructure problem, not a wrong answer)."""


def with_retry(send: Callable[[], httpx.Response], *, attempts: int = 3,
               sleep=time.sleep) -> httpx.Response:
    last = ""
    for i in range(attempts):
        try:
            resp = send()
        except httpx.TransportError as e:
            last = f"{type(e).__name__}: {e}"
        else:
            if resp.status_code not in RETRY_STATUS:
                if resp.is_error:
                    resp.raise_for_status()
                return resp
            last = f"HTTP {resp.status_code}"
        if i < attempts - 1:
            sleep(2 ** i)
    raise LLMUnavailable(f"LLM request failed after {attempts} attempts ({last})")
