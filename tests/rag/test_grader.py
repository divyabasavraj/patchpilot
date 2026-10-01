import dataclasses
import json

from cve_copilot.config import Settings
from cve_copilot.llm import fake
from cve_copilot.rag.grader import grade, rewrite_query
from cve_copilot.rag.models import Doc

FAKE = dataclasses.replace(Settings.from_env(), llm="fake")


def doc(i, aliases=(), summary="s", details="d" * 500):
    return Doc(i, aliases, ("pkg",), summary, details, None, False, False, None, ())


DOCS = [doc("GHSA-a", ("CVE-2020-1111",)), doc("GHSA-b"), doc("GHSA-c")]


def test_relevant_subset_kept_in_order():
    fake.set_responses([json.dumps({"relevant": ["GHSA-c", "GHSA-a"]})])
    g = grade("q", DOCS, settings=FAKE)
    assert [d.id for d in g.relevant] == ["GHSA-a", "GHSA-c"]
    assert g.verdicts == {"GHSA-a": True, "GHSA-b": False, "GHSA-c": True}
    assert g.error is None
    [call] = fake.calls
    assert call["json_mode"] is True
    prompt = call["messages"][-1]["content"]
    assert "[GHSA-b]" in prompt and "d" * 300 in prompt and "d" * 301 not in prompt


def test_grader_matches_aliases():
    fake.set_responses([json.dumps({"relevant": ["CVE-2020-1111"]})])
    assert [d.id for d in grade("q", DOCS, settings=FAKE).relevant] == ["GHSA-a"]


def test_grader_ignores_unknown_ids():
    fake.set_responses([json.dumps({"relevant": ["GHSA-zzz", "GHSA-b"]})])
    assert [d.id for d in grade("q", DOCS, settings=FAKE).relevant] == ["GHSA-b"]


def test_none_relevant():
    fake.set_responses([json.dumps({"relevant": []})])
    g = grade("q", DOCS, settings=FAKE)
    assert g.relevant == [] and g.error is None


def test_junk_reply_keeps_everything():
    for reply in ["no idea", '{"relevant": "GHSA-a"}', "[]"]:
        fake.set_responses([reply])
        g = grade("q", DOCS, settings=FAKE)
        assert g.relevant == DOCS and g.error == "grader reply unusable"


def test_no_docs_no_call():
    fake.set_responses([])
    assert grade("q", [], settings=FAKE).relevant == []
    assert fake.calls == []


def test_rewrite_strips_quotes_and_falls_back():
    fake.set_responses(['  "werkzeug debugger remote code execution"\n'])
    assert rewrite_query("can the debugger be abused?", settings=FAKE) == \
        "werkzeug debugger remote code execution"
    fake.set_responses(["   "])
    assert rewrite_query("original", settings=FAKE) == "original"
