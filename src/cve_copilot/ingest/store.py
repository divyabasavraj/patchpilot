"""Write advisories and KEV entries into a fresh SQLite database."""
import sqlite3
from pathlib import Path

from .models import Advisory, KevEntry

SCHEMA = """
CREATE TABLE advisories(id TEXT PRIMARY KEY, summary TEXT, details TEXT,
    published TEXT, modified TEXT, cvss_vector TEXT, cvss_score REAL,
    flagged INTEGER DEFAULT 0, flag_reason TEXT);
CREATE TABLE aliases(advisory_id TEXT, alias TEXT);
CREATE TABLE affected(advisory_id TEXT, package TEXT,
    introduced TEXT, fixed TEXT, last_affected TEXT);
CREATE TABLE affected_versions(advisory_id TEXT, package TEXT, version TEXT);
CREATE TABLE refs(advisory_id TEXT, type TEXT, url TEXT);
CREATE TABLE kev(cve_id TEXT PRIMARY KEY, date_added TEXT, ransomware TEXT);
CREATE INDEX idx_affected_pkg ON affected(package);
CREATE INDEX idx_versions_pkg ON affected_versions(package);
CREATE INDEX idx_alias ON aliases(alias);
"""


def write_db(path: Path, advisories: list[Advisory], kev: list[KevEntry]) -> None:
    if path.exists():
        raise FileExistsError(f"{path} already exists; build into a fresh folder")
    con = sqlite3.connect(path)
    try:
        con.executescript(SCHEMA)
        insert_advisories(con, advisories)
        con.executemany("INSERT OR IGNORE INTO kev VALUES (?,?,?)",
                        [(k.cve_id, k.date_added, k.ransomware) for k in kev])
        con.commit()
    finally:
        con.close()


def insert_advisories(con: sqlite3.Connection, advisories: list[Advisory]) -> None:
    con.executemany(
        "INSERT INTO advisories VALUES (?,?,?,?,?,?,?,?,?)",
        [(a.id, a.summary, a.details, a.published, a.modified,
          a.cvss_vector, a.cvss_score, int(a.flagged), a.flag_reason) for a in advisories])
    con.executemany("INSERT INTO aliases VALUES (?,?)",
                    [(a.id, al) for a in advisories for al in a.aliases])
    con.executemany("INSERT INTO affected VALUES (?,?,?,?,?)",
                    [(a.id, r.package, r.introduced, r.fixed, r.last_affected)
                     for a in advisories for r in a.ranges])
    con.executemany("INSERT INTO affected_versions VALUES (?,?,?)",
                    [(a.id, p, v) for a in advisories for p, v in a.versions])
    con.executemany("INSERT INTO refs VALUES (?,?,?)",
                    [(a.id, t, u) for a in advisories for t, u in a.refs])
