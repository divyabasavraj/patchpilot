"""Answers exam: run the whole answer loop and score citations, versions and groundedness (D33).

    uv run python -m evals.answers_exam [--target frozen|live]

Pass marks: citation accuracy >= 98%, groundedness >= 90%. Citation coverage (answers that
cite at least one ID), answer correctness and version accuracy are reported without a pass mark.
"""
import argparse
import json
import sys
from pathlib import Path

from cve_copilot import llm
from cve_copilot.config import Settings
from cve_copilot.embeddings import embed
from cve_copilot.rag.citations import find_ids, find_versions, unsupported_versions
from cve_copilot.rag.generator import scan_facts, source_text
from cve_copilot.rag.pipeline import Answer, answer
from cve_copilot.rag.retriever import EmbedFn
from cve_copilot.scanner import scan
from cve_copilot.scanner.models import ScanReport

CASES = Path(__file__).parent / "data" / "answers.jsonl"
PASS_MARKS = {"citation_accuracy": 0.98, "groundedness": 0.90}

_JUDGE_PROMPT = """\
You check whether an answer is fully supported by its sources. Reply with JSON only: \
{"grounded": true or false, "reason": "<one sentence>"}.
grounded is true only if every factual claim in the answer (what the bug does, affected or \
fixed versions, severity, whether it is exploited, which packages are affected) is stated \
in the sources or scanner facts, or follows directly from them. General advice such as \
"upgrade" or "avoid untrusted input" is fine. Any claim not in the sources makes it false."""


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


def _names(ans: Answer, report: ScanReport | None) -> set[str]:
    names = {n for d in ans.sources for n in (d.id, *d.aliases)}
    if report:
        names |= {n for f in report.findings for n in (f.advisory_id, *f.aliases)}
    return names


def _expected_hit(entry, ans: Answer, cited: set[str]) -> bool:
    """An expected bug counts if any of its IDs, or any alias of a source doc holding it, is cited."""
    wanted = set(entry if isinstance(entry, list) else [entry])
    for d in ans.sources:
        names = {d.id, *d.aliases}
        if names & wanted:
            wanted |= names
    return bool(wanted & cited)


def score(case: dict, ans: Answer, report: ScanReport | None, *,
          settings: Settings | None = None) -> dict:
    text = ans.text
    # Only generated answers cite; the fixed not-found message just repeats the asked ID.
    cited = list(find_ids(text)) if ans.trace.outcome == "answered" else []
    names = _names(ans, report)
    facts = "\n\n".join(p for p in (scan_facts(report), source_text(ans.sources)) if p)
    if case["expect_not_found"]:
        correct = ans.trace.outcome == "not_found" or not cited
    else:
        correct = (all(_expected_hit(e, ans, set(cited)) for e in case["expected_ids"])
                   and all(v in find_versions(text) for v in case["expected_versions"]))
    grounded, reason = (judge(text, facts, settings=settings) if ans.trace.outcome == "answered"
                        else (True, ans.trace.outcome))
    return {"id": case["id"], "outcome": ans.trace.outcome, "cited": cited,
            "citation_errors": [c for c in cited if c not in names],
            "versions": list(find_versions(text)),
            "unsupported_versions": list(unsupported_versions(text, facts)),
            "correct": correct, "grounded": grounded, "judge_reason": reason,
            "sources": [d.id for d in ans.sources], "answer": text}


def run(cases_path: Path, db_dir: Path, *, embed_fn: EmbedFn = embed,
        settings: Settings | None = None) -> dict:
    cases = [json.loads(line) for line in cases_path.read_text().splitlines() if line.strip()]
    results = []
    for case in cases:
        report = scan(case["requirements"], db_dir / "cve.db") if case.get("requirements") else None
        ans = answer(case["question"], db_dir, report=report, embed_fn=embed_fn, settings=settings)
        results.append(score(case, ans, report, settings=settings))
    cited = sum(len(r["cited"]) for r in results)
    errors = sum(len(r["citation_errors"]) for r in results)
    versions = sum(len(r["versions"]) for r in results)
    unsupported = sum(len(r["unsupported_versions"]) for r in results)
    n = len(results) or 1
    answered = [r for r in results if r["outcome"] == "answered"]
    return {
        "metric": "answers",
        "items": len(results),
        "citation_accuracy": round(1 - errors / cited, 4) if cited else 1.0,
        "citation_coverage": round(sum(bool(r["cited"]) for r in answered) / len(answered), 4)
                             if answered else 1.0,
        "groundedness": round(sum(r["grounded"] for r in results) / n, 4),
        "answer_correctness": round(sum(r["correct"] for r in results) / n, 4),
        "version_accuracy": round(1 - unsupported / versions, 4) if versions else 1.0,
        "results": results,
    }


def passes(result: dict) -> bool:
    return all(result[metric] >= mark for metric, mark in PASS_MARKS.items())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.answers_exam")
    parser.add_argument("--target", choices=["live", "frozen"], default="frozen")
    parser.add_argument("--report", type=Path, help="also write the full results here as JSON")
    args = parser.parse_args(argv)
    result = run(CASES, Settings.from_env().db_dir(args.target))
    if args.report:
        args.report.write_text(json.dumps(result, indent=2))
    summary = {k: v for k, v in result.items() if k != "results"}
    summary["not_passed"] = [{"id": r["id"], "correct": r["correct"], "grounded": r["grounded"],
                              "citation_errors": r["citation_errors"],
                              "unsupported_versions": r["unsupported_versions"]}
                             for r in result["results"]
                             if not (r["correct"] and r["grounded"]) or r["citation_errors"]]
    print(json.dumps(summary, indent=2))
    return 0 if passes(result) else 1


if __name__ == "__main__":
    sys.exit(main())
