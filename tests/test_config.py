from pathlib import Path

from cve_copilot.config import PROJECT_ROOT, Settings


def test_defaults(monkeypatch):
    for var in ["CVE_DATA_DIR", "LLM", "OLLAMA_URL", "OLLAMA_MODEL",
                "GITHUB_MODELS_URL", "GITHUB_MODEL", "GITHUB_TOKEN"]:
        monkeypatch.delenv(var, raising=False)
    s = Settings.from_env()
    assert s.data_dir == PROJECT_ROOT / "data"
    assert s.llm == "ollama"
    assert s.ollama_url == "http://localhost:11434"
    assert s.ollama_model == "qwen2.5:7b"
    assert s.github_model == "openai/gpt-4o-mini"
    assert s.github_token is None


def test_env_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LLM", "fake")
    s = Settings.from_env()
    assert s.data_dir == tmp_path
    assert s.llm == "fake"


def test_project_root_contains_pyproject():
    assert (PROJECT_ROOT / "pyproject.toml").exists()
