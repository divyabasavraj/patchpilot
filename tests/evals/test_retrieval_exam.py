import json
import sqlite3

from cve_copilot.config import Settings
from cve_copilot.llm import fake
from evals.retrieval_exam import CASES, run
from tests.rag.fixture_index import build_fixture, fake_embed


def write_cases(path, cases):
    path.write_text("".join(json.dumps(c) + "\n" for c in cases))
    return path


def test_scoring_counts_alias_hits_misses_and_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM", "fake")
    db_dir = build_fixture(tmp_path / "db")
    cases = write_cases(tmp_path / "c.jsonl", [
        # hit through an alias: the doc found is GHSA-sess-1, whose aliases include CVE-2023-1
        {"id": "a", "question": "Explain PYSEC-2023-1", "route": "id", "expected": ["CVE-2023-1"]},
        {"id": "b", "question": "flask problems", "route": "package", "expected": ["GHSA-pin-1"]},
        {"id": "c", "question": "What is CVE-1999-0001?", "route": "id", "expected": []},
        {"id": "d", "question": "hi", "route": "chat", "expected": []},
        {"id": "e", "question": "Explain CVE-2019-2222", "route": "id",
         "expected": [["NOPE-1", "GHSA-pin-1"]]},
    ])
    fake.set_responses([json.dumps({"route": "concept"})])   # only "hi" reaches the LLM
    result = run(cases, db_dir, embed_fn=fake_embed)
    by_id = {r["id"]: r for r in result["results"]}
    assert by_id["a"]["recall"] == 1.0
    assert by_id["b"]["recall"] == 0.0
    assert by_id["c"]["passed"] is True
    assert by_id["d"]["route_ok"] is False and by_id["d"]["passed"] is False
    assert by_id["e"]["recall"] == 1.0          # one of the alternatives was found
    assert result["recall_at_5"] == round(2 / 3, 4)
    assert result["route_accuracy"] == 0.8
    assert [f["id"] for f in result["failures"]] == ["b", "d"]


def test_expected_ids_exist_in_frozen_db():
    db = Settings.from_env().db_dir("frozen") / "cve.db"
    assert db.exists(), f"{db} is missing; build it first: uv run python -m cve_copilot.ingest --target frozen"
    con = sqlite3.connect(db)
    cases = [json.loads(line) for line in CASES.read_text().splitlines() if line.strip()]
    assert len(cases) >= 30
    for case in cases:
        assert case["route"] in {"id", "package", "concept", "chat"}
        for adv_id in (i for e in case["expected"] for i in (e if isinstance(e, list) else [e])):
            assert con.execute("SELECT 1 FROM advisories WHERE id = ?", (adv_id,)).fetchone(), adv_id
