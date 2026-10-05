"""The answer loop (spec 5.4 + 5.5), every step traced:

input guard → route → retrieve → context guard → grade (→ rewrite, retry once) → generate
→ output guard (→ regenerate once with the problems) → else facts written by code.
"""
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from ..embeddings import embed
from ..guards.context_guard import screen
from ..guards.input_guard import REFUSALS, check_input
from ..guards.output_guard import FALLBACK, check_answer, facts_text, find_exploit
from ..scanner.models import ScanReport
from . import search
from .generator import chat_reply, generate, scan_facts
from .grader import grade, rewrite_query
from .models import Doc, Route
from .retriever import EmbedFn, retrieve

NOT_FOUND = "I couldn't find this in the vulnerability database."
HIDDEN = ("I found this advisory, but its text contains instructions aimed at an AI, so I "
          "won't pass it to the language model. Here are its facts from the database:")
SCAN_SOURCES = 5   # advisories behind the most urgent scan findings, always given as sources (D34)


@dataclass
class Trace:
    route: Route | None = None         # None when the input guard refused the question
    retrieved: tuple[str, ...] = ()
    graded: tuple[str, ...] = ()       # documents passed to the generator
    from_scan: tuple[str, ...] = ()    # of those, added from the scan report (D34)
    rewritten_query: str | None = None
    retrieved_after_rewrite: tuple[str, ...] = ()
    grader_error: str | None = None
    input_label: str = "ok"            # input guard: ok | exploit_request | injection | off_topic
    input_by: str = ""                 # rules | llm | default
    dropped: tuple[tuple[str, str], ...] = ()          # context guard: (id, reason)
    output_issues: list[list[str]] = field(default_factory=list)   # output guard, per draft
    # answered | not_found | chat | refused | facts_only | fallback
    outcome: str = ""


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


def _screen(docs: list[Doc], trace: Trace) -> list[Doc]:
    kept, dropped = screen(docs)
    trace.dropped = tuple(dict.fromkeys(trace.dropped + dropped))
    return kept


def answer(question: str, db_dir: Path, *, report: ScanReport | None = None, k: int = 5,
           embed_fn: EmbedFn = embed, settings: Settings | None = None) -> Answer:
    verdict = check_input(question, settings=settings)
    trace = Trace(input_label=verdict.label, input_by=verdict.by)
    if verdict.blocked:
        trace.outcome = "refused"
        return Answer(REFUSALS[verdict.label], [], trace)

    trace.route, found = search(question, db_dir, k=k, embed_fn=embed_fn, settings=settings)
    route = trace.route
    trace.retrieved = _ids(found)

    if route.kind == "chat":
        trace.outcome = "chat"
        reply = chat_reply(question, settings=settings)
        if kind := find_exploit(reply):
            trace.output_issues.append([f"contains attack code ({kind})"])
            reply = REFUSALS["exploit_request"]
        return Answer(reply, [], trace)

    docs = _screen(found, trace)
    scan_docs = _screen(_scan_docs(report, db_dir), trace)
    if not docs and not scan_docs and trace.dropped and route.kind in ("id", "package"):
        # Everything asked for is flagged: code writes its facts, the LLM never reads it (D39).
        trace.outcome = "facts_only"
        return Answer(f"{HIDDEN}\n{facts_text(found)}", found, trace)

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
            again = retrieve(route, trace.rewritten_query, db_dir, k=k, embed_fn=embed_fn)
            trace.retrieved_after_rewrite = _ids(again)
            grades = grade(question, _screen(again, trace), settings=settings)
            trace.grader_error = trace.grader_error or grades.error
            relevant = grades.relevant
        if not relevant and not scan_docs:
            trace.outcome = "not_found"
            return Answer(NOT_FOUND, [], trace)

    named = set(_ids(relevant))
    extra = [d for d in scan_docs if d.id not in named]
    relevant = relevant + extra
    trace.from_scan = _ids(extra)
    trace.graded = _ids(relevant)

    facts = scan_facts(report)
    text = generate(question, relevant, facts, settings=settings)
    trace.output_issues.append(check_answer(text, relevant, facts, settings=settings))
    if trace.output_issues[-1]:
        text = generate(question, relevant, facts, feedback=trace.output_issues[-1],
                        settings=settings)
        trace.output_issues.append(check_answer(text, relevant, facts, settings=settings))
    if trace.output_issues[-1]:
        trace.outcome = "fallback"
        return Answer(f"{FALLBACK}\n{facts_text(relevant, facts)}", relevant, trace)
    trace.outcome = "answered"
    return Answer(text, relevant, trace)
