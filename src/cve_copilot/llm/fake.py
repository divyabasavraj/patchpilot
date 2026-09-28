"""Scripted LLM for unit tests: no network, fully predictable."""
_responses: list[str] = []
calls: list[dict] = []


def set_responses(responses: list[str]) -> None:
    _responses[:] = list(responses)
    calls.clear()


def complete(messages: list[dict], *, json_mode: bool = False) -> str:
    calls.append({"messages": messages, "json_mode": json_mode})
    if not _responses:
        raise AssertionError("fake LLM has no scripted response left")
    return _responses.pop(0)
