import json

from cve_copilot.llm import fake
from evals.answers_exam import CASES, passes, run
from tests.rag.fixture_index import build_fixture, fake_embed


def write_cases(path, cases):
    path.write_text("".join(json.dumps(c) + "\n" for c in cases))
    return path


def test_citation_accuracy_counts_invented_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM", "fake")
    db_dir = build_fixture(tmp_path / "db")
    cases = write_cases(tmp_path / "a.jsonl", [
        {"id": "a", "question": "What is CVE-2024-9999?", "expected_ids": ["GHSA-sql-1"],
         "expected_versions": ["4.2.1"], "expect_not_found": False},
        {"id": "b", "question": "What is CVE-1999-0001?", "expected_ids": [],
         "expected_versions": [], "expect_not_found": True},
    ])
    fake.set_responses([
        "SQL injection [CVE-2024-9999], see also [CVE-2020-5555]. Fixed in 4.2.1, or 9.9.9.",
        json.dumps({"grounded": False, "reason": "9.9.9 is not in the sources"}),
    ])
    result = run(cases, db_dir, embed_fn=fake_embed)
    a, b = result["results"]
    assert a["cited"] == ["CVE-2024-9999", "CVE-2020-5555"]
    assert a["citation_errors"] == ["CVE-2020-5555"]
    assert a["correct"] is True                       # the alias of GHSA-sql-1 counts
    assert a["unsupported_versions"] == ["9.9.9"]
    assert a["grounded"] is False and "9.9.9" in a["judge_reason"]
    assert b["outcome"] == "not_found" and b["correct"] is True and b["grounded"] is True
    assert result["citation_accuracy"] == 0.5
    assert result["citation_coverage"] == 1.0         # the one generated answer cites something
    assert result["groundedness"] == 0.5
    assert result["answer_correctness"] == 1.0
    assert result["version_accuracy"] == 0.5
    assert not passes(result)


def test_judge_junk_counts_as_not_grounded(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM", "fake")
    db_dir = build_fixture(tmp_path / "db")
    cases = write_cases(tmp_path / "a.jsonl", [
        {"id": "a", "question": "What is CVE-2024-9999?", "expected_ids": ["GHSA-sql-1"],
         "expected_versions": ["9.9.9"], "expect_not_found": False}])
    fake.set_responses(["SQL injection [CVE-2024-9999].", "hmm"])
    [a] = run(cases, db_dir, embed_fn=fake_embed)["results"]
    assert a["grounded"] is False and a["correct"] is False   # expected version missing


def test_scan_finding_ids_are_valid_citations(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM", "fake")
    db_dir = build_fixture(tmp_path / "db")
    cases = write_cases(tmp_path / "a.jsonl", [
        {"id": "a", "question": "What is CVE-2019-2222?", "requirements": "flask==2.2.0\n",
         "expected_ids": ["GHSA-pin-1"], "expected_versions": [], "expect_not_found": False}])
    fake.set_responses(["Debugger [CVE-2019-2222]; your flask has [CVE-2023-1].",
                        json.dumps({"grounded": True, "reason": ""})])
    result = run(cases, db_dir, embed_fn=fake_embed)
    assert result["citation_accuracy"] == 1.0 and passes(result)


def test_exam_file_shape():
    cases = [json.loads(line) for line in CASES.read_text().splitlines() if line.strip()]
    assert len(cases) == 20
    assert sum(c["expect_not_found"] for c in cases) == 2
    assert all(c["expected_ids"] for c in cases if not c["expect_not_found"])
