"""Output guard (spec 5.5): check a generated answer before the user sees it (D41).

Code checks: cited IDs are sources, versions appear in the sources, something is cited, no
attack code. Only if those pass does the LLM judge check groundedness (saves a call).
"""
import json
import re

from .. import llm
from ..config import Settings
from ..rag.citations import find_ids, unsupported_versions
from ..rag.generator import source_text
from ..rag.models import Doc

UNGROUNDED = "makes claims the sources do not support"
_BRACKETED = re.compile(r"\[([A-Za-z]{2,}-[\w.-]+)\]")
FALLBACK = "I couldn't give a reliable answer, so here are the facts from the database:"

_F = re.IGNORECASE
EXPLOIT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("script-tag", re.compile(r"<\s*script\b|\bon(?:error|load)\s*=", _F)),
    ("sql-payload", re.compile(r"'\s*or\s*'?1'?\s*=\s*'?1|\bunion\s+(?:all\s+)?select\b", _F)),
    ("shell-payload", re.compile(r"/bin/(?:ba)?sh\b|\bbash\s+-i\b|/dev/tcp/|\bnc\s+(?:-\w+\s+)*-e\b"
                                 r"|\bmkfifo\b", _F)),
    ("pipe-to-shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", _F)),
    # With an argument only: "the eval() call" is an explanation, eval('...') is code.
    ("python-exec", re.compile(r"__import__\(|\b(?:os\.system|eval|exec|subprocess\.\w+)\(\s*[^)\s]")),
    ("pickle-payload", re.compile(r"__reduce__")),
]

_JUDGE_PROMPT = """\
You check whether an answer is fully supported by its sources. Reply with JSON only: \
{"grounded": true or false, "reason": "<one sentence>"}.
grounded is true only if every factual claim in the answer (what the bug does, affected or \
fixed versions, severity, whether it is exploited, which packages are affected) is stated \
in the sources or scanner facts, or follows directly from them. General advice such as \
"upgrade" or "avoid untrusted input" is fine. Any claim not in the sources makes it false."""


def find_exploit(text: str) -> str | None:
    for name, pattern in EXPLOIT_PATTERNS:
        if pattern.search(text):
            return name
    return None


def cited_ids(text: str) -> tuple[str, ...]:
    """IDs in the usual formats, plus anything ID-like in square brackets (catches odd made-up IDs)."""
    found = list(find_ids(text))
    seen = {f.upper() for f in found}
    for raw in _BRACKETED.findall(text):
        if raw.upper() not in seen:
            seen.add(raw.upper())
            found.append(raw)
    return tuple(found)


def judge(text: str, facts: str, *, settings: Settings | None = None) -> tuple[bool, str]:
    reply = llm.complete([
        {"role": "system", "content": _JUDGE_PROMPT},
        {"role": "user", "content": f"Sources and facts:\n{facts}\n\nAnswer:\n{text}"},
    ], json_mode=True, settings=settings)
    try:
        verdict = json.loads(reply)
        return verdict["grounded"] is True, str(verdict.get("reason", ""))
    except (ValueError, TypeError, KeyError):
        return False, f"judge reply unusable: {reply[:80]!r}"   # strict: unknown counts as a fail


def check_answer(text: str, docs: list[Doc], facts: str, *,
                 settings: Settings | None = None) -> list[str]:
    """Problems with the answer, worded as instructions for a rewrite; [] if it passes."""
    all_sources = "\n\n".join(p for p in (facts, source_text(docs)) if p)
    names = {n for d in docs for n in (d.id, *d.aliases)} | set(find_ids(facts))
    cited = cited_ids(text)
    issues = []
    if not cited:
        issues.append("cites no source: end every fact with its source ID in square brackets")
    if bad := [c for c in cited if c not in names]:
        issues.append(f"cites IDs that are not among the sources: {', '.join(bad)}")
    if versions := unsupported_versions(text, all_sources):
        issues.append(f"mentions versions that are not in the sources: {', '.join(versions)}; "
                      "only write versions exactly as the sources give them")
    if kind := find_exploit(text):
        issues.append(f"contains attack code ({kind}); explain the problem without code or payloads")
    if not issues:
        grounded, reason = judge(text, all_sources, settings=settings)
        if not grounded:
            issues.append(f"{UNGROUNDED}: {reason}")
    return issues


def facts_text(docs: list[Doc], facts: str = "") -> str:
    """Facts written by code only, for when the LLM's answer can't be trusted or used."""
    lines = []
    for d in docs:
        cvss = f"CVSS {d.cvss_score:.1f}" if d.cvss_score is not None else "CVSS unknown"
        lines.append(f"- [{d.id}] {d.summary or '(no summary)'}\n"
                     f"  Packages: {', '.join(d.packages)}. Affected: "
                     f"{'; '.join(d.affected) or 'unknown'}. {cvss}. "
                     f"Known exploited (CISA KEV): {'yes' if d.in_kev else 'no'}.")
    if facts:
        lines.append(facts)
    return "\n".join(lines)
