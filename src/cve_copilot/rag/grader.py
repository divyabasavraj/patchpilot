"""Grade retrieved documents in one LLM call (D29), and rewrite a query for one retry."""
import json
from dataclasses import dataclass, field

from .. import llm
from ..config import Settings
from .models import Doc

DETAIL_CHARS = 300
_GRADE_PROMPT = """\
You check search results for an assistant that answers questions about security \
vulnerabilities in Python packages. For each advisory below, decide whether it helps \
answer the user's question. Reply with JSON only: {"relevant": ["<ID>", ...]}, listing the \
IDs of the helpful advisories, or {"relevant": []} if none helps."""
_REWRITE_PROMPT = """\
Rewrite the user's question as a short search query for a database of Python security \
advisories: name the kind of bug, the affected component and the package if known. \
Reply with the query only."""


@dataclass
class Grades:
    relevant: list[Doc]
    verdicts: dict[str, bool] = field(default_factory=dict)
    error: str | None = None


def _listing(docs: list[Doc]) -> str:
    return "\n".join(f"[{d.id}] {d.summary} — {d.details[:DETAIL_CHARS]}" for d in docs)


def grade(question: str, docs: list[Doc], *, settings: Settings | None = None) -> Grades:
    if not docs:
        return Grades([])
    reply = llm.complete([
        {"role": "system", "content": _GRADE_PROMPT},
        {"role": "user", "content": f"Question: {question}\n\nAdvisories:\n{_listing(docs)}"},
    ], json_mode=True, settings=settings)
    try:
        named = json.loads(reply)["relevant"]
        if not isinstance(named, list):
            raise TypeError
    except (ValueError, TypeError, KeyError):
        # Keep everything: a formatting slip must not turn into "I don't know" (D31).
        return Grades(list(docs), {d.id: True for d in docs}, "grader reply unusable")
    named = {str(n) for n in named}
    verdicts = {d.id: bool(named & {d.id, *d.aliases}) for d in docs}
    return Grades([d for d in docs if verdicts[d.id]], verdicts)


def rewrite_query(question: str, *, settings: Settings | None = None) -> str:
    reply = llm.complete([{"role": "system", "content": _REWRITE_PROMPT},
                          {"role": "user", "content": question}], settings=settings)
    query = reply.strip().strip("\"'").strip()
    return query or question
