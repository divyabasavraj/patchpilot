"""Plain helpers for the Streamlit app (app.py): no Streamlit here, so they are unit-tested."""
import json
from pathlib import Path

import httpx

from .config import Settings
from .rag.__main__ import format_trace
from .rag.models import Doc
from .rag.pipeline import Trace
from .scanner.__main__ import upgrade_text
from .scanner.models import ScanReport

OSV_URL = "https://osv.dev/vulnerability/"


def osv_url(advisory_id: str) -> str:
    return OSV_URL + advisory_id


def pick_target(settings: Settings) -> str | None:
    """live data when it has been built or pulled, else the frozen snapshot, else None."""
    for target in ("live", "frozen"):
        if (settings.db_dir(target) / "cve.db").exists():
            return target
    return None


def manifest(db_dir: Path) -> dict | None:
    path = db_dir / "manifest.json"
    return json.loads(path.read_text()) if path.exists() else None


def finding_rows(report: ScanReport) -> list[dict]:
    return [{"Package": f.package, "Version": f.version, "Advisory": osv_url(f.advisory_id),
             "CVSS": f.cvss_score, "Flag": "MALWARE" if f.is_malware else ("KEV" if f.in_kev else ""),
             "Fix": f.upgrade_to or "no fix known", "Summary": f.summary}
            for f in report.findings]


def upgrade_lines(report: ScanReport) -> list[str]:
    versions = {p.name: p.version for p in report.checked}
    return [f"{pkg} {versions[pkg]}{upgrade_text(up)}" for pkg, up in report.upgrades.items()]


def source_lines(docs: list[Doc]) -> list[str]:
    lines = []
    for d in docs:
        facts = [", ".join(d.packages)]
        if d.cvss_score is not None:
            facts.append(f"CVSS {d.cvss_score:.1f}")
        if d.in_kev:
            facts.append("KEV")
        lines.append(f"- [{d.id}]({osv_url(d.id)}) · {' · '.join(facts)}: {d.summary}")
    return lines


def trace_text(trace: Trace) -> str:
    return format_trace(trace)


def ollama_status(settings: Settings, client: httpx.Client | None = None) -> str | None:
    """None when the configured model can answer; otherwise what the user should do."""
    if settings.llm != "ollama":
        return None
    client = client or httpx.Client(timeout=3)
    try:
        tags = client.get(f"{settings.ollama_url}/api/tags").json()
    except (httpx.HTTPError, ValueError):
        return "Ollama is not running. Start it with: `ollama serve`"
    names = {m.get("name") for m in tags.get("models", [])}
    if settings.ollama_model not in names:
        return f"Model {settings.ollama_model} is missing. Run: `ollama pull {settings.ollama_model}`"
    return None


def reload_data() -> None:
    """Forget cached DB handles after the data folder was swapped (nightly pull, D50)."""
    import chromadb

    from .rag import retriever
    retriever.package_names.cache_clear()
    retriever._collection.cache_clear()
    chromadb.api.client.SharedSystemClient.clear_system_cache()
