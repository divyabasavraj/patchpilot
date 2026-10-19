"""One function to call whichever LLM is configured (LLM=ollama|fake)."""
from ..config import Settings
from . import fake, ollama


def complete(messages: list[dict], *, json_mode: bool = False,
             settings: Settings | None = None) -> str:
    s = settings or Settings.from_env()
    if s.llm == "fake":
        return fake.complete(messages, json_mode=json_mode)
    if s.llm == "ollama":
        return ollama.complete(messages, json_mode=json_mode, settings=s)
    raise ValueError(f"Unknown LLM provider: {s.llm!r} (use ollama or fake)")
