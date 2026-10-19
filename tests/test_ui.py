import json

import httpx

from cve_copilot import ui
from cve_copilot.config import Settings
from cve_copilot.rag.models import Doc, Route
from cve_copilot.rag.pipeline import Trace
from cve_copilot.scanner import scan

from .rag.fixture_index import build_fixture


def settings(tmp_path, llm="ollama"):
    return Settings(data_dir=tmp_path, llm=llm, ollama_url="http://ollama", ollama_model="qwen2.5:7b")


def doc(**kw):
    base = dict(id="GHSA-1", aliases=("CVE-2024-1",), packages=("flask",), summary="Bad cookie",
                details="", cvss_score=7.5, in_kev=True, flagged=False, flag_reason=None,
                affected=())
    return Doc(**(base | kw))


def test_osv_url():
    assert ui.osv_url("GHSA-abc") == "https://osv.dev/vulnerability/GHSA-abc"


def test_pick_target_prefers_live_then_frozen(tmp_path):
    s = settings(tmp_path)
    assert ui.pick_target(s) is None
    (tmp_path / "frozen" / "db").mkdir(parents=True)
    (tmp_path / "frozen" / "db" / "cve.db").touch()
    assert ui.pick_target(s) == "frozen"
    (tmp_path / "live").mkdir()
    (tmp_path / "live" / "cve.db").touch()
    assert ui.pick_target(s) == "live"


def test_manifest(tmp_path):
    assert ui.manifest(tmp_path) is None
    (tmp_path / "manifest.json").write_text(json.dumps({"built_at": "2026-10-11T00:00:00+00:00"}))
    assert ui.manifest(tmp_path)["built_at"].startswith("2026-10-11")


def test_finding_rows_and_upgrades(tmp_path):
    db_dir = build_fixture(tmp_path / "db")
    report = scan("django==3.0\nreqeusts==1.0\nflask\n", db_dir / "cve.db")
    rows = ui.finding_rows(report)
    by_id = {r["Advisory"].rsplit("/", 1)[1]: r for r in rows}
    assert by_id["GHSA-sql-1"] | {"Advisory": ""} == {
        "Package": "django", "Version": "3.0", "Advisory": "", "CVSS": 9.8, "Flag": "KEV",
        "Fix": "4.2.1", "Summary": "SQL injection in the ORM"}
    assert by_id["MAL-2024-1"]["Flag"] == "MALWARE"
    assert by_id["MAL-2024-1"]["Fix"] == "no fix known"
    lines = ui.upgrade_lines(report)
    assert "django 3.0 -> 4.2.1" in lines
    assert any(line.startswith("reqeusts 1.0") for line in lines)


def test_source_lines():
    [line] = ui.source_lines([doc()])
    assert line.startswith("- [GHSA-1](https://osv.dev/vulnerability/GHSA-1)")
    assert "flask" in line and "CVSS 7.5" in line and "KEV" in line and "Bad cookie" in line
    [line] = ui.source_lines([doc(cvss_score=None, in_kev=False)])
    assert "CVSS" not in line and "KEV" not in line


def test_trace_text():
    t = Trace(route=Route("concept", by="llm"), retrieved=("A", "B"), graded=("A",),
              outcome="answered")
    assert ui.trace_text(t).startswith("route=concept (llm), retrieved=2, relevant=1, outcome=answered")
    refused = Trace(route=None, input_label="exploit_request", input_by="rules", outcome="refused")
    assert ui.trace_text(refused) == "input guard=exploit_request (rules), outcome=refused"


def transport(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ollama_status_ok_missing_model_and_down(tmp_path):
    s = settings(tmp_path)
    ok = transport(lambda r: httpx.Response(200, json={"models": [{"name": "qwen2.5:7b"}]}))
    assert ui.ollama_status(s, client=ok) is None
    other = transport(lambda r: httpx.Response(200, json={"models": [{"name": "qwen2.5:3b"}]}))
    assert "ollama pull qwen2.5:7b" in ui.ollama_status(s, client=other)

    def refuse(request):
        raise httpx.ConnectError("refused")
    assert "ollama serve" in ui.ollama_status(s, client=transport(refuse))


def test_ollama_status_skipped_for_other_llms(tmp_path):
    assert ui.ollama_status(settings(tmp_path, llm="fake")) is None
