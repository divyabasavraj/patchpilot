import json

import pytest

from evals.make_scan_cases import check_parse, expected_flags
from evals.scan_exam import run
from tests.scanner.fixture_db import build_fixture_db


def write_cases(path, cases):
    path.write_text("".join(json.dumps(c) + "\n" for c in cases))
    return path


def case(id, requirements, records, flags, not_pinned=(), skipped=(), **extra):
    return {"id": id, "requirements": requirements,
            "expected": {"records": records, "flags": flags,
                         "not_pinned": list(not_pinned), "skipped": list(skipped)}, **extra}


NO_FLAGS = {"malware": False, "kev": False}


def test_run_scores_exact_matches(tmp_path):
    db = build_fixture_db(tmp_path / "cve.db")
    cases = write_cases(tmp_path / "cases.jsonl", [
        case("right", "flask==2.2.0\nurllib3\n-r x.txt\n",
             {"flask": ["PYSEC-2023-1", "GHSA-flask-1", "GHSA-flask-2"]}, {"flask": NO_FLAGS}, [2], [3]),
        case("wrong", "flask==3.1.3\n", {"flask": ["GHSA-flask-2"]}, {"flask": NO_FLAGS}),
    ])
    result = run(cases, db)
    assert result["metric"] == "scanner_accuracy"
    assert (result["cases"], result["passed"], result["accuracy"]) == (2, 1, 0.5)
    [failure] = result["failures"]
    assert failure["id"] == "wrong"
    assert failure["got"]["records"] == {}


def test_run_checks_malware_and_kev_flags(tmp_path):
    db = build_fixture_db(tmp_path / "cve.db")
    both = {"django": {"malware": False, "kev": True}, "reqeusts": {"malware": True, "kev": False}}
    records = {"django": ["GHSA-dj-1", "GHSA-dj-2"], "reqeusts": ["MAL-2024-1"]}
    cases = write_cases(tmp_path / "cases.jsonl", [
        case("right", "django==4.0\nreqeusts==1.0\n", records, both),
        case("kev-missed", "django==4.0\nreqeusts==1.0\n", records,
             {**both, "django": NO_FLAGS}),
    ])
    result = run(cases, db)
    assert [f["id"] for f in result["failures"]] == ["kev-missed"]
    assert result["failures"][0]["got"]["flags"] == both


def test_known_differences_exclude_exactly_those_ids(tmp_path):
    db = build_fixture_db(tmp_path / "cve.db")
    cases = write_cases(tmp_path / "cases.jsonl", [
        # The answer key did not list GHSA-bad-1 (its bound "2.6.0-cu124" is salvaged by us).
        case("documented", "badlib==2.6.5\nflask==3.1.3\n", {}, {},
             known_differences=["GHSA-bad-1"]),
        case("other-ids-still-count", "badlib==2.6.5\nflask==2.3.0rc1\n", {}, {},
             known_differences=["GHSA-bad-1"]),
    ])
    result = run(cases, db)
    assert [f["id"] for f in result["failures"]] == ["other-ids-still-count"]


def test_expected_flags_come_from_the_raw_snapshot(tmp_path):
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "GHSA-a.json").write_text(json.dumps({"id": "GHSA-a", "aliases": ["CVE-1"]}))
    (osv / "MAL-1.json").write_text(json.dumps({"id": "MAL-1"}))
    (osv / "GHSA-b.json").write_text(json.dumps({"id": "GHSA-b", "aliases": ["CVE-2"]}))
    flags = expected_flags({"x": ["GHSA-a"], "y": ["MAL-1", "GHSA-b"]}, osv, {"CVE-1"})
    assert flags == {"x": {"malware": False, "kev": True}, "y": {"malware": True, "kev": False}}


def test_check_parse_compares_hand_written_pins():
    text = "Flask==2.2.0\nurllib3\n"
    check_parse("ok", text, [("flask", "2.2.0")], [2], [])
    with pytest.raises(SystemExit, match="pins"):
        check_parse("bad", text, [("flask", "2.2.1")], [2], [])
    with pytest.raises(SystemExit, match="not_pinned"):
        check_parse("bad", text, [("flask", "2.2.0")], [], [])
