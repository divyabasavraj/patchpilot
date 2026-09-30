"""Settings read from environment variables, plus project paths."""
import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    llm: str
    ollama_url: str
    ollama_model: str
    github_url: str
    github_model: str
    github_token: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get
        return cls(
            data_dir=Path(env("CVE_DATA_DIR", str(PROJECT_ROOT / "data"))),
            llm=env("LLM", "ollama"),
            ollama_url=env("OLLAMA_URL", "http://localhost:11434"),
            ollama_model=env("OLLAMA_MODEL", "qwen2.5:7b"),
            # Endpoint and model are re-checked when CI is set up (Phase 6).
            github_url=env("GITHUB_MODELS_URL",
                           "https://models.github.ai/inference/chat/completions"),
            github_model=env("GITHUB_MODEL", "openai/gpt-4o-mini"),
            github_token=env("GITHUB_TOKEN"),
        )

    def db_dir(self, target: str) -> Path:
        """Folder holding cve.db, chroma/ and manifest.json for a build target."""
        if target == "live":
            return self.data_dir / "live"
        if target == "frozen":
            return self.data_dir / "frozen" / "db"
        raise ValueError(f"Unknown target {target!r} (use live or frozen)")
