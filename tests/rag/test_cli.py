import json

from cve_copilot.llm import fake
from cve_copilot.rag.__main__ import main

from .fixture_index import build_fixture, fake_embed


def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("LLM", "fake")
    build_fixture(tmp_path / "data" / "live")


def test_cli_id_question(tmp_path, monkeypatch, capsys):
    setup(tmp_path, monkeypatch)
    assert main(["What is CVE-2024-9999?"], embed_fn=fake_embed) == 0
    out = capsys.readouterr().out
    assert "Route: id (rules) ids=CVE-2024-9999" in out
    assert "GHSA-sql-1" in out and "KEV" in out


def test_cli_concept_question_uses_llm_route(tmp_path, monkeypatch, capsys):
    setup(tmp_path, monkeypatch)
    fake.set_responses([json.dumps({"route": "concept"})])
    assert main(["cross site trouble", "-k", "1"], embed_fn=fake_embed) == 0
    out = capsys.readouterr().out
    assert "Route: concept (llm)" in out and "GHSA-xss-1" in out


def test_cli_chat_question(tmp_path, monkeypatch, capsys):
    setup(tmp_path, monkeypatch)
    fake.set_responses([json.dumps({"route": "chat"})])
    assert main(["hello"], embed_fn=fake_embed) == 0
    assert "No search needed." in capsys.readouterr().out


def test_cli_missing_db(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path / "data"))
    assert main(["What is CVE-2024-9999?"], embed_fn=fake_embed) == 2
    assert "Build it first" in capsys.readouterr().err
