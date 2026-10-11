"""The Streamlit page, driven headless with AppTest; the answer loop is stubbed (tested in rag/)."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from cve_copilot.llm.retry import LLMUnavailable
from cve_copilot.rag import pipeline
from cve_copilot.rag.models import Route

from .rag.fixture_index import build_fixture

APP = str(Path(__file__).parents[1] / "src" / "cve_copilot" / "app.py")


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LLM", "fake")
    build_fixture(tmp_path / "frozen" / "db")
    return AppTest.from_file(APP, default_timeout=30)


def test_no_data_explains_how_to_get_it(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert "--pull-release" in at.sidebar.error[0].value


def test_sidebar_and_scan(app):
    at = app.run()
    assert not at.exception
    assert "frozen" in at.sidebar.markdown[0].value
    at.text_area(key="pasted").input("django==3.0\nflask\n")
    next(b for b in at.button if b.label == "Scan").click().run()
    assert not at.exception
    assert [m.value for m in at.metric] == ["1", "2", "1"]
    assert "django 3.0 -> 4.2.1" in at.code[0].value
    assert "Not checked" in at.expander[0].label


def test_chat_shows_answer_sources_and_trace(app, monkeypatch):
    seen = {}

    def fake_answer(question, db_dir, *, report=None, settings=None):
        seen["question"], seen["report"] = question, report
        docs = pipeline.retrieve(Route("id", ids=("GHSA-pin-1",)), "", db_dir)
        trace = pipeline.Trace(route=Route("id", ids=("GHSA-pin-1",)), outcome="answered")
        return pipeline.Answer("The PIN is guessable [GHSA-pin-1].", docs, trace)

    monkeypatch.setattr(pipeline, "answer", fake_answer)
    at = app.run()
    at.chat_input[0].set_value("What is GHSA-pin-1?").run()
    assert not at.exception
    assert seen == {"question": "What is GHSA-pin-1?", "report": None}
    texts = [m.value for m in at.markdown]
    assert "The PIN is guessable [GHSA-pin-1]." in texts
    assert any("https://osv.dev/vulnerability/GHSA-pin-1" in t for t in texts)
    assert "outcome=answered" in at.code[-1].value


def test_chat_when_model_is_down(app, monkeypatch):
    def down(*args, **kwargs):
        raise LLMUnavailable("Is Ollama running? Start it with: ollama serve")

    monkeypatch.setattr(pipeline, "answer", down)
    at = app.run()
    at.chat_input[0].set_value("hello").run()
    assert not at.exception
    assert any("ollama serve" in m.value for m in at.markdown)
