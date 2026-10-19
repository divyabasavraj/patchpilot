from pathlib import Path

import pytest

from cve_copilot.config import PROJECT_ROOT, Settings


def test_defaults(monkeypatch):
    for var in ["CVE_DATA_DIR", "LLM", "OLLAMA_URL", "OLLAMA_MODEL"]:
        monkeypatch.delenv(var, raising=False)
    s = Settings.from_env()
    assert s.data_dir == PROJECT_ROOT / "data"
    assert s.llm == "ollama"
    assert s.ollama_url == "http://localhost:11434"
    assert s.ollama_model == "qwen2.5:7b"
    assert not hasattr(s, "github_token")


def test_env_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LLM", "fake")
    s = Settings.from_env()
    assert s.data_dir == tmp_path
    assert s.llm == "fake"


def test_project_root_contains_pyproject():
    assert (PROJECT_ROOT / "pyproject.toml").exists()


def test_db_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    s = Settings.from_env()
    assert s.db_dir("live") == tmp_path / "live"
    assert s.db_dir("frozen") == tmp_path / "frozen" / "db"
    with pytest.raises(ValueError):
        s.db_dir("other")
