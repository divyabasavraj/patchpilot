"""Retrieval exam: route + retrieve every question, score recall@5 against hand-picked IDs.

    uv run python -m evals.retrieval_exam [--target frozen|live]

A hit is an expected ID that is the main ID or an alias of one of the top-k documents (D27).
An expected entry may be a list of alternatives (the same bug in several packages): any one hits.
Items with no expected IDs pass when nothing comes back (unknown ID) or the route is chat.
"""
import argparse
import json
import sys
from pathlib import Path

from cve_copilot.config import Settings
from cve_copilot.embeddings import embed
from cve_copilot.rag import search
from cve_copilot.rag.retriever import EmbedFn
from evals import thresholds

CASES = Path(__file__).parent / "data" / "retrieval.jsonl"


def _score(case: dict, route, docs) -> dict:
    found_ids = {n for d in docs for n in (d.id, *d.aliases)}
    expected = case["expected"]
    route_ok = route.kind == case["route"]
    result = {"id": case["id"], "route": route.kind, "route_by": route.by, "route_ok": route_ok,
              "got": [d.id for d in docs]}
    if expected:
        alternatives = [e if isinstance(e, list) else [e] for e in expected]
        result["recall"] = sum(bool(found_ids & set(alt)) for alt in alternatives) / len(expected)
        result["passed"] = result["recall"] == 1.0
    elif case["route"] == "chat":
        result["passed"] = route_ok
    else:
        result["passed"] = not docs
    return result


def run(cases_path: Path, db_dir: Path, *, k: int = 5, embed_fn: EmbedFn = embed,
        settings: Settings | None = None) -> dict:
    cases = [json.loads(line) for line in cases_path.read_text().splitlines() if line.strip()]
    results = [_score(c, *search(c["question"], db_dir, k=k, embed_fn=embed_fn, settings=settings))
               for c in cases]
    recalls = [r["recall"] for r in results if "recall" in r]
    return {
        "metric": "retrieval_recall_at_5",
        "items": len(recalls),
        "recall_at_5": round(sum(recalls) / len(recalls), 4) if recalls else 0.0,
        "route_accuracy": round(sum(r["route_ok"] for r in results) / len(results), 4),
        "failures": [r for r in results if not r["passed"]],
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.retrieval_exam")
    parser.add_argument("--target", choices=["live", "frozen"], default="frozen")
    args = parser.parse_args(argv)
    result = run(CASES, Settings.from_env().db_dir(args.target))
    print(json.dumps({key: val for key, val in result.items() if key != "results"}, indent=2))
    return 1 if thresholds.check("retrieval", result) else 0


if __name__ == "__main__":
    sys.exit(main())
