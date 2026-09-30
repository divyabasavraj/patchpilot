"""Read one package's advisories from the ingest SQLite database (read-only)."""
import sqlite3
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from ..ingest.models import AffectedRange
from .models import Record


def open_db(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise FileNotFoundError(
            f"No vulnerability database at {path}. "
            "Build it first: uv run python -m cve_copilot.ingest --target live (or frozen)")
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)


def load_records(con: sqlite3.Connection, package: str) -> list[Record]:
    ranges: dict[str, list[AffectedRange]] = defaultdict(list)
    for adv_id, intro, fixed, last in con.execute(
            "SELECT advisory_id, introduced, fixed, last_affected FROM affected WHERE package = ?",
            (package,)):
        ranges[adv_id].append(AffectedRange(package, intro, fixed, last))
    versions: dict[str, list[str]] = defaultdict(list)
    for adv_id, version in con.execute(
            "SELECT advisory_id, version FROM affected_versions WHERE package = ?", (package,)):
        versions[adv_id].append(version)

    ids = sorted(ranges.keys() | versions.keys())
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    aliases: dict[str, list[str]] = defaultdict(list)
    for adv_id, alias in con.execute(
            f"SELECT advisory_id, alias FROM aliases WHERE advisory_id IN ({marks})", ids):
        aliases[adv_id].append(alias)
    rows = con.execute(
        f"SELECT id, summary, cvss_score FROM advisories WHERE id IN ({marks}) ORDER BY id", ids)
    return [Record(adv_id, tuple(sorted(aliases[adv_id])), (summary or "").strip(), score,
                   tuple(ranges[adv_id]), tuple(versions[adv_id]))
            for adv_id, summary, score in rows]


def kev_ids(con: sqlite3.Connection, ids: Iterable[str]) -> set[str]:
    wanted = sorted(set(ids))
    if not wanted:
        return set()
    marks = ",".join("?" * len(wanted))
    return {row[0] for row in con.execute(f"SELECT cve_id FROM kev WHERE cve_id IN ({marks})", wanted)}
