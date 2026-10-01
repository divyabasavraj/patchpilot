"""Build the answer prompt (question + scanner facts + labelled sources) and call the LLM."""
from .. import llm
from ..config import Settings
from ..scanner.__main__ import upgrade_text
from ..scanner.models import ScanReport
from .models import Doc

DETAIL_CHARS = 1200
MAX_FACT_FINDINGS = 30   # keep the prompt small for a 7B model (D32)

_ANSWER_PROMPT = """\
You are CVE Copilot. You explain security vulnerabilities in Python packages in plain \
English to developers who are not security experts.

Rules:
- Use only the facts in the sources and the scanner facts below. Do not use outside knowledge.
- Every sentence with a fact must end with the ID of its source in square brackets, exactly as \
it appears at the start of that source, e.g. "Fixed in 2.2.5 [GHSA-m2qf-hxjv-5gpq]." An answer \
without citations is wrong. Only cite the IDs that start a source; never cite other IDs you see \
inside a source's text.
- Only mention version numbers that appear in the sources or scanner facts. Never guess a version.
- If the sources do not answer the question, say so clearly instead of guessing.
- Never write exploit code, attack payloads or step-by-step attack instructions.
- Be short: at most about 200 words. Say what the problem is, who is affected, and how to fix it."""

_CHAT_PROMPT = """\
You are CVE Copilot, an assistant for security vulnerabilities in Python packages. \
Reply briefly and kindly. You may explain general security terms in simple words. \
Never state facts about specific vulnerabilities, advisory IDs or version numbers here. \
Suggest asking about a package, an advisory ID such as a CVE, or uploading a requirements.txt."""


def source_text(docs: list[Doc]) -> str:
    blocks = []
    for d in docs:
        head = f"[{d.id}]" + (f" also known as: {', '.join(d.aliases)}" if d.aliases else "")
        cvss = f"{d.cvss_score:.1f}" if d.cvss_score is not None else "unknown"
        blocks.append("\n".join([
            head,
            f"Packages: {', '.join(d.packages)} | CVSS: {cvss} | "
            f"Known exploited (CISA KEV): {'yes' if d.in_kev else 'no'}",
            f"Affected: {'; '.join(d.affected) or 'unknown'}",
            f"Summary: {d.summary}",
            f"Details: {d.details[:DETAIL_CHARS]}",
        ]))
    return "\n\n".join(blocks)


def scan_facts(report: ScanReport | None) -> str:
    if report is None:
        return ""
    lines = [f"Scan of the user's requirements file: {len(report.checked)} pinned packages "
             f"checked, {len(report.findings)} findings."]
    for f in report.findings[:MAX_FACT_FINDINGS]:
        tags = [f"CVSS {f.cvss_score:.1f}" if f.cvss_score is not None else "CVSS unknown"]
        tags += [t for t, on in (("KEV", f.in_kev), ("MALWARE", f.is_malware)) if on]
        fix = f"fixed in {f.upgrade_to}" if f.upgrade_to else "no fixed version known"
        lines.append(f"- {f.package} {f.version}: {f.advisory_id} ({', '.join(tags)}) {fix}"
                     + (f": {f.summary[:80]}" if f.summary else ""))
    hidden = len(report.findings) - MAX_FACT_FINDINGS
    if hidden > 0:
        lines.append(f"(and {hidden} more findings not shown)")
    if report.upgrades:
        versions = {p.name: p.version for p in report.checked}
        lines.append("Suggested upgrades:")
        lines += [f"  {pkg} {versions[pkg]}{upgrade_text(up)}" for pkg, up in report.upgrades.items()]
    if report.not_pinned:
        lines.append("Not checked (not pinned): " + ", ".join(n.line for n in report.not_pinned))
    return "\n".join(lines)


def generate(question: str, docs: list[Doc], facts: str, *,
             settings: Settings | None = None) -> str:
    parts = [f"Question: {question}"]
    if facts:
        parts.append(f"Scanner facts:\n{facts}")
    parts.append(f"Sources:\n{source_text(docs)}")
    return llm.complete([{"role": "system", "content": _ANSWER_PROMPT},
                         {"role": "user", "content": "\n\n".join(parts)}], settings=settings)


def chat_reply(question: str, *, settings: Settings | None = None) -> str:
    return llm.complete([{"role": "system", "content": _CHAT_PROMPT},
                         {"role": "user", "content": question}], settings=settings)
