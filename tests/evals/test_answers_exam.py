import json

from cve_copilot.llm import fake
from cve_copilot.rag.models import Route
from cve_copilot.rag.pipeline import Answer, Trace
from cve_copilot.rag.retriever import retrieve
from evals import answers_exam
from evals.answers_exam import CASES, passes, run
from tests.rag.fixture_index import build_fixture, fake_embed


def write_cases(path, cases):
    path.write_text("".join(json.dumps(c) + "\n" for c in cases))
    return path


GOOD = json.dumps({"grounded": True, "reason": ""})


def scripted_answers(monkeypatch, db_dir, answers):
    """Replace the answer loop with fixed answers, so only the scoring is tested."""
    queue = list(answers)

    def fake_answer(question, db, **kw):
        text, ids, outcome, drafts = queue.pop(0)
        docs = retrieve(Route("id", ids=tuple(ids)), "", db_dir) if ids else []
        return Answer(text, docs, Trace(Route("id", ids=tuple(ids)), outcome=outcome,
                                        output_issues=drafts))
    monkeypatch.setattr(answers_exam, "answer", fake_answer)


def test_citation_accuracy_counts_invented_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM", "fake")
    db_dir = build_fixture(tmp_path / "db")
    cases = write_cases(tmp_path / "a.jsonl", [
        {"id": "a", "question": "What is CVE-2024-9999?", "expected_ids": ["GHSA-sql-1"],
         "expected_versions": ["4.2.1"], "expect_not_found": False},
        {"id": "b", "question": "What is CVE-1999-0001?", "expected_ids": [],
         "expected_versions": [], "expect_not_found": True},
    ])
    scripted_answers(monkeypatch, db_dir, [
        ("SQL injection [CVE-2024-9999], see also [CVE-2020-5555]. Fixed in 4.2.1, or 9.9.9.",
         ["CVE-2024-9999"], "answered", [[]]),
        ("I couldn't find CVE-1999-0001 in the vulnerability database.", [], "not_found", []),
    ])
    fake.set_responses([json.dumps({"grounded": False, "reason": "9.9.9 is not in the sources"})])
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
    scripted_answers(monkeypatch, db_dir, [("SQL injection [CVE-2024-9999].", ["CVE-2024-9999"],
                                            "answered", [[]])])
    fake.set_responses(["hmm"])
    [a] = run(cases, db_dir, embed_fn=fake_embed)["results"]
    assert a["grounded"] is False and a["correct"] is False   # expected version missing


def test_scan_finding_ids_are_valid_citations(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM", "fake")
    db_dir = build_fixture(tmp_path / "db")
    cases = write_cases(tmp_path / "a.jsonl", [
        {"id": "a", "question": "What is CVE-2019-2222?", "requirements": "flask==2.2.0\n",
         "expected_ids": ["GHSA-pin-1"], "expected_versions": [], "expect_not_found": False}])
    scripted_answers(monkeypatch, db_dir, [
        ("Debugger [CVE-2019-2222]; your flask has [CVE-2023-1].", ["CVE-2019-2222"],
         "answered", [[]])])
    fake.set_responses([GOOD])
    result = run(cases, db_dir, embed_fn=fake_embed)
    assert result["citation_accuracy"] == 1.0 and passes(result)


def test_guard_outcomes_and_first_drafts(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM", "fake")
    db_dir = build_fixture(tmp_path / "db")
    case = {"question": "What is CVE-2024-9999?", "expected_ids": ["GHSA-sql-1"],
            "expected_versions": ["4.2.1"], "expect_not_found": False}
    cases = write_cases(tmp_path / "a.jsonl", [{"id": i, **case} for i in "abc"])
    scripted_answers(monkeypatch, db_dir, [
        # judged ungrounded at first, fixed on the rewrite
        ("SQL injection, fixed in 4.2.1 [GHSA-sql-1].", ["GHSA-sql-1"], "answered",
         [["makes claims the sources do not support: x"], []]),
        # first draft failed a code check (not judged), then fell back to code-made facts
        ("I couldn't give a reliable answer ...\n- [GHSA-sql-1] SQL injection. fixed in 4.2.1",
         ["GHSA-sql-1"], "fallback", [["cites no source"], ["cites no source"]]),
        ("SQL injection, fixed in 4.2.1 [GHSA-sql-1].", ["GHSA-sql-1"], "answered", [[]]),
    ])
    fake.set_responses([GOOD, GOOD])          # the exam judges the two LLM answers
    result = run(cases, db_dir, embed_fn=fake_embed)
    a, b, c = result["results"]
    assert (a["first_draft_grounded"], b["first_draft_grounded"], c["first_draft_grounded"]) == (
        False, None, True)
    assert result["first_draft_groundedness"] == 0.5 and result["first_drafts_judged"] == 2
    assert result["regenerated"] == 2 and result["fallbacks"] == 1
    assert b["correct"] is True and b["cited"] == [] and b["grounded"] is True
    assert result["citation_coverage"] == 1.0


def test_exam_file_shape():
    cases = [json.loads(line) for line in CASES.read_text().splitlines() if line.strip()]
    assert len(cases) == 21
    assert sum(c["expect_not_found"] for c in cases) == 2
    assert all(c["expected_ids"] for c in cases if not c["expect_not_found"])
