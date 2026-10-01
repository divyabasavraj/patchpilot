"""The answer loop (spec 5.4): route, retrieve, grade, retry once, generate; every step traced.

Guards (input, context, output) join in Phase 5.
"""
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from ..embeddings import embed
from ..scanner.models import ScanReport
from . import search
from .generator import chat_reply, generate, scan_facts
from .grader import grade, rewrite_query
from .models import Doc, Route
from .retriever import EmbedFn, retrieve

NOT_FOUND = "I couldn't find this in the vulnerability database."
SCAN_SOURCES = 5   # advisories behind the most urgent scan findings, always given as sources (D34)


@dataclass
class Trace:
    route: Route
    retrieved: tuple[str, ...] = ()
    graded: tuple[str, ...] = ()       # documents passed to the generator
    from_scan: tuple[str, ...] = ()    # of those, added from the scan report (D34)
    rewritten_query: str | None = None
    retrieved_after_rewrite: tuple[str, ...] = ()
    grader_error: str | None = None
    outcome: str = ""                 # "answered" | "not_found" | "chat"


@dataclass
class Answer:
    text: str
    sources: list[Doc] = field(default_factory=list)
    trace: Trace | None = None


def _ids(docs: list[Doc]) -> tuple[str, ...]:
    return tuple(d.id for d in docs)


def _scan_docs(report: ScanReport | None, db_dir: Path) -> list[Doc]:
    if not report or not report.findings:
        return []
    ids = tuple(dict.fromkeys(f.advisory_id for f in report.findings))[:SCAN_SOURCES]
    return retrieve(Route("id", ids=ids), "", db_dir)


def answer(question: str, db_dir: Path, *, report: ScanReport | None = None, k: int = 5,
           embed_fn: EmbedFn = embed, settings: Settings | None = None) -> Answer:
    route, docs = search(question, db_dir, k=k, embed_fn=embed_fn, settings=settings)
    trace = Trace(route, retrieved=_ids(docs))

    if route.kind == "chat":
        trace.outcome = "chat"
        return Answer(chat_reply(question, settings=settings), [], trace)

    scan_docs = _scan_docs(report, db_dir)
    if route.kind == "id":
        relevant = docs   # the user named them, so they are relevant by definition (D30)
        if not relevant and not scan_docs:
            trace.outcome = "not_found"
            return Answer(f"I couldn't find {', '.join(route.ids)} in the vulnerability database.",
                          [], trace)
    else:
        grades = grade(question, docs, settings=settings)
        trace.grader_error = grades.error
        relevant = grades.relevant
        if not relevant:
            trace.rewritten_query = rewrite_query(question, settings=settings)
            docs = retrieve(route, trace.rewritten_query, db_dir, k=k, embed_fn=embed_fn)
            trace.retrieved_after_rewrite = _ids(docs)
            grades = grade(question, docs, settings=settings)
            trace.grader_error = trace.grader_error or grades.error
            relevant = grades.relevant
        if not relevant and not scan_docs:
            trace.outcome = "not_found"
            return Answer(NOT_FOUND, [], trace)

    found = set(_ids(relevant))
    extra = [d for d in scan_docs if d.id not in found]
    relevant = relevant + extra
    trace.from_scan = _ids(extra)
    trace.graded = _ids(relevant)
    trace.outcome = "answered"
    return Answer(generate(question, relevant, scan_facts(report), settings=settings), relevant, trace)
