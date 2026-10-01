import dataclasses
import json

import pytest

from cve_copilot.config import Settings
from cve_copilot.llm import fake
from cve_copilot.rag.pipeline import NOT_FOUND, answer
from cve_copilot.scanner import scan

from .fixture_index import build_fixture, fake_embed

FAKE = dataclasses.replace(Settings.from_env(), llm="fake")


@pytest.fixture(scope="module")
def db_dir(tmp_path_factory):
    return build_fixture(tmp_path_factory.mktemp("pipe") / "db")


def ask(question, db_dir, **kw):
    return answer(question, db_dir, embed_fn=fake_embed, settings=FAKE, **kw)


def prompts():
    return [c["messages"][-1]["content"] for c in fake.calls]


def test_chat_route_skips_search(db_dir):
    fake.set_responses([json.dumps({"route": "chat"}), "Hello! Ask me about a package."])
    a = ask("hello", db_dir)
    assert a.text == "Hello! Ask me about a package."
    assert a.sources == [] and a.trace.outcome == "chat" and a.trace.retrieved == ()
    assert len(fake.calls) == 2


def test_id_route_skips_grader(db_dir):
    fake.set_responses(["It is a SQL injection [GHSA-sql-1]."])
    a = ask("What is CVE-2024-9999?", db_dir)
    assert [d.id for d in a.sources] == ["GHSA-sql-1"]
    assert a.trace.route.kind == "id" and a.trace.graded == ("GHSA-sql-1",)
    assert a.trace.outcome == "answered" and len(fake.calls) == 1
    assert "[GHSA-sql-1]" in prompts()[0]


def test_unknown_id_not_found_without_llm_generation(db_dir):
    fake.set_responses([])
    a = ask("What is CVE-1999-0001?", db_dir)
    assert a.text == "I couldn't find CVE-1999-0001 in the vulnerability database."
    assert a.trace.outcome == "not_found" and fake.calls == []


def test_relevant_docs_go_to_generator(db_dir):
    fake.set_responses([json.dumps({"relevant": ["GHSA-sql-2"]}), "Admin filters [GHSA-sql-2]."])
    a = ask("sql trouble in django", db_dir)
    assert [d.id for d in a.sources] == ["GHSA-sql-2"]
    assert a.trace.graded == ("GHSA-sql-2",) and len(a.trace.retrieved) == 3
    assert "[GHSA-sql-2]" in prompts()[1] and "[GHSA-xss-1]" not in prompts()[1]


def test_rewrite_once_then_not_found(db_dir):
    fake.set_responses([json.dumps({"relevant": []}), "django admin sql",
                        json.dumps({"relevant": []})])
    a = ask("django question", db_dir)
    assert a.text == NOT_FOUND and a.sources == []
    assert a.trace.rewritten_query == "django admin sql" and a.trace.outcome == "not_found"
    assert len(fake.calls) == 3          # grade, rewrite, grade: no generation


def test_rewrite_finds_docs(db_dir):
    fake.set_responses([json.dumps({"route": "concept"}), json.dumps({"relevant": []}),
                        "cross site scripting", json.dumps({"relevant": ["GHSA-xss-1"]}),
                        "XSS [GHSA-xss-1]."])
    a = ask("something odd in my templates", db_dir)
    assert a.trace.rewritten_query == "cross site scripting"
    assert a.trace.retrieved_after_rewrite[0] == "GHSA-xss-1"
    assert [d.id for d in a.sources] == ["GHSA-xss-1"] and a.trace.outcome == "answered"


def test_grader_error_is_traced(db_dir):
    fake.set_responses(["not json", "answer"])
    a = ask("django sql", db_dir)
    assert a.trace.grader_error == "grader reply unusable" and len(a.sources) == 3


def test_scan_facts_reach_prompt(db_dir):
    report = scan("flask==2.2.0\n", db_dir / "cve.db")
    fake.set_responses([json.dumps({"relevant": ["GHSA-sess-1"]}), "Upgrade [GHSA-sess-1]."])
    ask("is my flask ok?", db_dir, report=report)
    assert "Scanner facts:\nScan of the user's requirements file" in prompts()[1]
    assert "- flask 2.2.0: GHSA-sess-1" in prompts()[1]


def test_scan_docs_are_always_sources(db_dir):
    report = scan("flask==2.2.0\ndjango==3.0\n", db_dir / "cve.db")
    fake.set_responses([json.dumps({"route": "concept"}), json.dumps({"relevant": []}),
                        "something", json.dumps({"relevant": []}), "Fix django first [GHSA-sql-1]."])
    a = ask("which of my packages should I fix first?", db_dir, report=report)
    assert a.trace.outcome == "answered"
    assert set(a.trace.from_scan) == {"GHSA-sql-1", "GHSA-sql-2", "GHSA-sess-1"}
    assert "[GHSA-sql-1]" in prompts()[-1]
