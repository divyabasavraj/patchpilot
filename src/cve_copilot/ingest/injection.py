"""Find hidden instructions aimed at an AI inside advisory text."""
import re

_F = re.IGNORECASE

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore-instructions", re.compile(
        r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+|your\s+)?"
        r"(previous|prior|above|earlier)\s+(instructions|prompts?|rules)", _F)),
    ("new-instructions", re.compile(r"\bnew\s+instructions\s*:", _F)),
    ("role-hijack", re.compile(r"\byou\s+are\s+now\s+(a|an|the)\b", _F)),
    ("system-prompt", re.compile(
        r"\b(reveal|print|show|repeat|output)\s+(your\s+|the\s+)?system\s+prompt", _F)),
    ("chat-markup", re.compile(r"<\|im_(start|end)\|>|\[/?INST\]|<</?SYS>>", _F)),
    ("assistant-directive", re.compile(
        r"\b(AI|assistant|chatbot|language model|LLM)\s*[,:]\s*(you must|always|never|do not)\b", _F)),
]


def scan_text(text: str) -> str | None:
    for name, pattern in PATTERNS:
        if pattern.search(text):
            return name
    return None
