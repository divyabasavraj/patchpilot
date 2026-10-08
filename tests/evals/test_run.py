import json

import pytest

from cve_copilot.llm.retry import LLMUnavailable
from evals import answers_exam, guards_exam, run as runner_mod
from evals.run import (EXAMS, SampleError, exit_code, load_sample, main, run, run_exam,
                       subset, to_markdown)

GOOD = {
    "scan": {"accuracy": 1.0, "cases": 26},
    "retrieval": {"recall_at_5": 0.95, "items": 33},
    "answers": {"citation_accuracy": 1.0, "groundedness": 0.95, "items": 8},
    "guards": {"block_rate": 1.0, "false_block_rate": 0.0, "attacks": [{}] * 10,
               "benign": [{}] * 8},
}


def fake_runner(results, crash_on=None, error=None):
    calls = []

    def runner(name, db_dir, sample, tmp):
        calls.append(name)
        if name == crash_on:
            raise error
        return results[name]
    runner.calls = calls
    return runner


@pytest.fixture
def db_dir(tmp_path):
    d = tmp_path / "db"
    d.mkdir()
    (d / "cve.db").write_bytes(b"")
    return d


def write_jsonl(path, ids):
    path.write_text("".join(json.dumps({"id": i, "question": f"q {i}"}) + "\n" for i in ids))
    return path


def test_all_pass_is_exit_0(db_dir):
    report = run(EXAMS, db_dir, runner=fake_runner(GOOD))
    assert exit_code(report) == 0
    md = to_markdown(report)
    assert "| guards | false_block_rate | 0.0% | ≤ 5.0% | 10 attacks, 8 benign | ✅ |" in md
    assert "**PASS:**" in md


def test_score_below_mark_is_exit_1(db_dir):
    results = {**GOOD, "retrieval": {"recall_at_5": 0.879, "items": 33}}
    report = run(EXAMS, db_dir, runner=fake_runner(results))
    assert exit_code(report) == 1
    assert report["exams"]["retrieval"]["misses"] == [
        {"metric": "recall_at_5", "score": 0.879, "mark": 0.90, "upper": False}]
    assert "| retrieval | recall_at_5 | 87.9% | ≥ 90.0% | 33 | ❌ |" in to_markdown(report)


@pytest.mark.parametrize("error", [LLMUnavailable("Is Ollama running?"),
                                   KeyError("exam 'answers' did not report 'groundedness'")])
def test_crash_keeps_finished_exams_and_names_the_crash(db_dir, error):
    fake = fake_runner(GOOD, crash_on="answers", error=error)
    report = run(EXAMS, db_dir, runner=fake)
    assert exit_code(report) == 2
    assert list(report["exams"]) == ["scan", "retrieval"]
    assert report["error"]["exam"] == "answers"
    assert type(error).__name__ in report["error"]["message"]
    assert fake.calls == ["scan", "retrieval", "answers"]          # guards never started
    assert "**ERROR in answers:**" in to_markdown(report)


def test_missing_db_is_exit_2_and_creates_nothing(tmp_path):
    db_dir = tmp_path / "db"
    fake = fake_runner(GOOD)
    report = run(EXAMS, db_dir, runner=fake)
    assert exit_code(report) == 2 and fake.calls == []
    assert "ingest --target" in report["error"]["message"]
    assert not db_dir.exists()


def test_subset_keeps_only_listed_ids(tmp_path):
    src = write_jsonl(tmp_path / "all.jsonl", ["a", "b", "c"])
    out = subset(src, ["c", "a"], tmp_path / "some.jsonl")
    assert [json.loads(line)["id"] for line in out.read_text().splitlines()] == ["a", "c"]


def test_load_sample_rejects_unknown_ids_and_wrong_lists(tmp_path):
    files = {"answers": write_jsonl(tmp_path / "a.jsonl", ["a1", "a2"])}
    sample = tmp_path / "s.toml"
    sample.write_text('answers = ["a1", "a9"]\n')
    with pytest.raises(SampleError, match="a9"):
        load_sample(sample, files)
    sample.write_text('answers = ["a1"]\nextra = ["x"]\n')
    with pytest.raises(SampleError, match="exactly"):
        load_sample(sample, files)
    sample.write_text('answers = ["a1"]\n')
    assert load_sample(sample, files) == {"answers": ["a1"]}


def test_committed_sample_is_valid_and_covers_every_attack_kind():
    sample = load_sample()
    kinds = {json.loads(line)["id"]: json.loads(line)["kind"]
             for line in guards_exam.ATTACKS.read_text().splitlines() if line.strip()}
    picked = [kinds[i] for i in sample["attacks"]]
    assert all(picked.count(k) >= 2 for k in ("question", "planted", "flagged"))
    assert "bn21" in sample["benign"]


def test_run_exam_hands_the_sample_to_the_exams(tmp_path, monkeypatch):
    seen = {}

    def fake_answers(cases, db):
        seen["answers"] = cases

    def fake_guards(attacks, benign, db):
        seen["guards"] = (attacks, benign)
    monkeypatch.setattr(answers_exam, "run", fake_answers)
    monkeypatch.setattr(guards_exam, "run", fake_guards)
    ids = lambda p: [json.loads(line)["id"] for line in p.read_text().splitlines()]

    sample = {"answers": ["nf-lottery"], "attacks": ["ex1", "pl1"], "benign": ["bn21"]}
    run_exam("answers", tmp_path, sample, tmp_path)
    run_exam("guards", tmp_path, sample, tmp_path)
    assert ids(seen["answers"]) == ["nf-lottery"]
    assert ids(seen["guards"][0]) == ["ex1", "pl1"] and ids(seen["guards"][1]) == ["bn21"]

    run_exam("answers", tmp_path, None, tmp_path)          # no sample: the full file
    assert seen["answers"] == answers_exam.CASES


def test_bad_sample_stops_before_any_exam(tmp_path, monkeypatch):
    def no_exam(*a, **kw):
        raise AssertionError("no exam may run with a bad sample")

    def bad_sample():
        raise SampleError("ci_sample.toml: answers has IDs not in answers.jsonl: zz")
    monkeypatch.setattr(runner_mod, "run", no_exam)
    monkeypatch.setattr(runner_mod, "load_sample", bad_sample)
    assert main(["--sample", "--out", str(tmp_path)]) == 2
    assert "zz" in (tmp_path / "report.md").read_text()


@pytest.mark.parametrize("value", [None, ""])
def test_step_summary_written_only_when_set(tmp_path, monkeypatch, value):
    monkeypatch.setattr(runner_mod, "run",
                        lambda exams, db_dir, sample=None: {"sample": False, "exams": {},
                                                            "error": None})
    monkeypatch.chdir(tmp_path)
    if value is None:
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    else:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", value)
    assert main(["--exams", "scan", "--out", str(tmp_path)]) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.json", "report.md"]


def test_step_summary_appended_when_set(tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    summary.write_text("earlier step\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setattr(runner_mod, "run",
                        lambda exams, db_dir, sample=None: {"sample": False, "exams": {},
                                                            "error": None})
    main(["--exams", "scan", "--out", str(tmp_path)])
    text = summary.read_text()
    assert text.startswith("earlier step\n") and "CVE Copilot exams" in text


def test_unknown_exam_name_is_a_usage_error(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["--exams", "scan,nope", "--out", str(tmp_path)])
    assert exc.value.code == 2
