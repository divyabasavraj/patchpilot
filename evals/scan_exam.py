"""Scan exam: run the scanner on every case and compare with the answer key (exact match).

    uv run python -m evals.scan_exam [--target frozen|live]
"""
import argparse
import json
import sys
from pathlib import Path

from cve_copilot.config import Settings
from cve_copilot.scanner import scan
from cve_copilot.scanner.models import ScanReport

CASES = Path(__file__).parent / "data" / "scan_cases.jsonl"


def _answer(report: ScanReport) -> dict:
    records: dict[str, set[str]] = {}
    for f in report.findings:
        records.setdefault(f.package, set()).update(f.records)
    return {"records": {p: sorted(ids) for p, ids in sorted(records.items())},
            "not_pinned": [n.line_no for n in report.not_pinned],
            "skipped": [n.line_no for n in report.skipped]}


def _normalise(expected: dict) -> dict:
    return {"records": {p: sorted(ids) for p, ids in sorted(expected["records"].items()) if ids},
            "not_pinned": expected["not_pinned"], "skipped": expected["skipped"]}


def run(cases_path: Path, db_path: Path) -> dict:
    cases = [json.loads(line) for line in cases_path.read_text().splitlines() if line.strip()]
    failures = []
    for case in cases:
        got, want = _answer(scan(case["requirements"], db_path)), _normalise(case["expected"])
        if got != want:
            failures.append({"id": case["id"], "expected": want, "got": got})
    passed = len(cases) - len(failures)
    return {"metric": "scanner_accuracy", "cases": len(cases), "passed": passed,
            "accuracy": passed / len(cases) if cases else 0.0, "failures": failures}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.scan_exam")
    parser.add_argument("--target", choices=["live", "frozen"], default="frozen")
    args = parser.parse_args(argv)
    result = run(CASES, Settings.from_env().db_dir(args.target) / "cve.db")
    print(json.dumps(result, indent=2))
    return 0 if result["accuracy"] == 1.0 else 1


if __name__ == "__main__":
    sys.exit(main())
