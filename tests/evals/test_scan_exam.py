import json

from evals.scan_exam import run
from tests.scanner.fixture_db import build_fixture_db


def write_cases(path, cases):
    path.write_text("".join(json.dumps(c) + "\n" for c in cases))
    return path


def test_run_scores_exact_matches(tmp_path):
    db = build_fixture_db(tmp_path / "cve.db")
    cases = write_cases(tmp_path / "cases.jsonl", [
        {"id": "right", "requirements": "flask==2.2.0\nurllib3\n-r x.txt\n",
         "expected": {"records": {"flask": ["PYSEC-2023-1", "GHSA-flask-1", "GHSA-flask-2"]},
                      "not_pinned": [2], "skipped": [3]}},
        {"id": "wrong", "requirements": "flask==3.1.3\n",
         "expected": {"records": {"flask": ["GHSA-flask-2"]}, "not_pinned": [], "skipped": []}},
    ])
    result = run(cases, db)
    assert result["metric"] == "scanner_accuracy"
    assert (result["cases"], result["passed"], result["accuracy"]) == (2, 1, 0.5)
    [failure] = result["failures"]
    assert failure["id"] == "wrong"
    assert failure["got"]["records"] == {}
