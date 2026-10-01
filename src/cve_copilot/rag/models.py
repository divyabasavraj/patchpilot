"""Data objects passed between the RAG steps."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Route:
    kind: str                         # "id" | "package" | "concept" | "chat"
    ids: tuple[str, ...] = ()         # advisory IDs named in the question
    packages: tuple[str, ...] = ()    # canonical package names found in the question
    by: str = "rules"                 # "rules" | "llm" | "default" (LLM reply unusable)


@dataclass(frozen=True)
class Doc:
    """One bug, merged from every stored record of it (e.g. GHSA + PYSEC)."""
    id: str                           # main ID: GHSA, then PYSEC, then others
    aliases: tuple[str, ...]          # every other ID for the same bug
    packages: tuple[str, ...]
    summary: str
    details: str
    cvss_score: float | None
    in_kev: bool
    flagged: bool                     # injection-like text found at ingest
    flag_reason: str | None
    affected: tuple[str, ...]         # readable ranges, e.g. "flask: from 0, fixed in 2.2.5"
    score: float | None = None        # similarity to the question; None for exact lookups
