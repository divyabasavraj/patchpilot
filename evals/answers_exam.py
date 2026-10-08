"""Answers exam: run the whole answer loop and score citations, versions and groundedness (D33).

    uv run python -m evals.answers_exam [--target frozen|live]

Pass marks: evals/thresholds.toml (citation accuracy, groundedness). Citation coverage (answers that
cite at least one ID), answer correctness and version accuracy are reported without a pass mark.
Since Phase 5 the output guard runs the same judge before the user sees an answer, so the
exam also reports first-draft groundedness (from the trace) and how often drafts were
regenerated or replaced by code-made facts (D42).
"""
import argparse
import json
import sys
from pathlib import Path

from cve_copilot.config import Settings
from cve_copilot.embeddings import embed
from cve_copilot.guards.output_guard import UNGROUNDED, cited_ids, judge
from cve_copilot.rag.citations import find_versions, unsupported_versions
from cve_copilot.rag.generator import scan_facts, source_text
from cve_copilot.rag.pipeline import Answer, answer
from cve_copilot.rag.retriever import EmbedFn
from cve_copilot.scanner import scan
from cve_copilot.scanner.models import ScanReport
from evals import thresholds

CASES = Path(__file__).parent / "data" / "answers.jsonl"

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
    text, outcome = ans.text, ans.trace.outcome
    # Only LLM answers are scored for citations; the not-found message just repeats the asked
    # ID, and fallback / facts-only text is written by code.
    cited = list(cited_ids(text)) if outcome == "answered" else []
    shown = list(cited_ids(text)) if outcome in ("answered", "fallback", "facts_only") else []
    names = _names(ans, report)
    facts = "\n\n".join(p for p in (scan_facts(report), source_text(ans.sources)) if p)
    if case["expect_not_found"]:
        correct = outcome == "not_found" or not shown
    else:
        correct = (all(_expected_hit(e, ans, set(shown)) for e in case["expected_ids"])
                   and all(v in find_versions(text) for v in case["expected_versions"]))
    drafts = ans.trace.output_issues
    first = drafts[0] if drafts else []
    # None: the first draft failed a code check, so the guard did not ask the judge.
    first_grounded = (None if not drafts or (first and not first[0].startswith(UNGROUNDED))
                      else not first)
    grounded, reason = (judge(text, facts, settings=settings) if outcome == "answered"
                        else (True, outcome))
    return {"id": case["id"], "outcome": outcome, "cited": cited,
            "first_draft_grounded": first_grounded, "output_issues": drafts,
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
    judged = [r["first_draft_grounded"] for r in results if r["first_draft_grounded"] is not None]
    return {
        "metric": "answers",
        "items": len(results),
        "citation_accuracy": round(1 - errors / cited, 4) if cited else 1.0,
        "citation_coverage": round(sum(bool(r["cited"]) for r in answered) / len(answered), 4)
                             if answered else 1.0,
        "groundedness": round(sum(r["grounded"] for r in results) / n, 4),
        "answer_correctness": round(sum(r["correct"] for r in results) / n, 4),
        "version_accuracy": round(1 - unsupported / versions, 4) if versions else 1.0,
        "first_draft_groundedness": round(sum(judged) / len(judged), 4) if judged else 1.0,
        "first_drafts_judged": len(judged),
        "regenerated": sum(len(r["output_issues"]) > 1 for r in results),
        "fallbacks": sum(r["outcome"] == "fallback" for r in results),
        "results": results,
    }


def passes(result: dict) -> bool:
    return not thresholds.check("answers", result)


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
                              "outcome": r["outcome"], "citation_errors": r["citation_errors"],
                              "output_issues": r["output_issues"],
                              "unsupported_versions": r["unsupported_versions"]}
                             for r in result["results"]
                             if not (r["correct"] and r["grounded"]) or r["citation_errors"]]
    print(json.dumps(summary, indent=2))
    return 0 if passes(result) else 1


if __name__ == "__main__":
    sys.exit(main())
