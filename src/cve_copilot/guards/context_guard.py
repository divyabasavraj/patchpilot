"""Context guard (spec 5.5): the LLM never reads documents with hidden instructions.

A document is dropped if it was flagged at ingest or its text matches today's patterns (D38).
"""
from ..ingest.injection import scan_text
from ..rag.models import Doc


def screen(docs: list[Doc]) -> tuple[list[Doc], tuple[tuple[str, str], ...]]:
    """(documents to keep, (id, reason) for each dropped one)."""
    kept, dropped = [], []
    for d in docs:
        reason = (d.flag_reason or "flagged") if d.flagged else scan_text(f"{d.summary}\n{d.details}")
        if reason:
            dropped.append((d.id, reason))
        else:
            kept.append(d)
    return kept, tuple(dropped)
