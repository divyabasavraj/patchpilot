import sqlite3

import pytest

from cve_copilot.ingest.models import Advisory, AffectedRange, KevEntry
from cve_copilot.ingest.store import write_db


def adv(**kw):
    base = dict(
        id="GHSA-1", summary="s", details="d", published="p", modified="m",
        cvss_vector="CVSS:3.1/X", cvss_score=7.5,
        aliases=["CVE-2024-1"],
        ranges=[AffectedRange("django", "3.0", "3.2.5", None)],
        versions=[("django", "3.0")],
        refs=[("WEB", "https://x")],
        flagged=True, flag_reason="role-hijack",
    )
    base.update(kw)
    return Advisory(**base)


def test_write_db_roundtrip(tmp_path):
    db = tmp_path / "cve.db"
    write_db(db, [adv()], [KevEntry("CVE-2024-1", "2024-01-01", "Unknown")])
    con = sqlite3.connect(db)
    assert con.execute("SELECT id, cvss_score, flagged, flag_reason FROM advisories").fetchall() == [
        ("GHSA-1", 7.5, 1, "role-hijack")]
    assert con.execute("SELECT advisory_id, alias FROM aliases").fetchall() == [("GHSA-1", "CVE-2024-1")]
    assert con.execute("SELECT * FROM affected").fetchall() == [("GHSA-1", "django", "3.0", "3.2.5", None)]
    assert con.execute("SELECT * FROM affected_versions").fetchall() == [("GHSA-1", "django", "3.0")]
    assert con.execute("SELECT * FROM refs").fetchall() == [("GHSA-1", "WEB", "https://x")]
    assert con.execute("SELECT * FROM kev").fetchall() == [("CVE-2024-1", "2024-01-01", "Unknown")]


def test_duplicate_kev_ids_do_not_crash(tmp_path):
    kev = [KevEntry("CVE-1", "a", "x"), KevEntry("CVE-1", "b", "y")]
    write_db(tmp_path / "cve.db", [], kev)
    con = sqlite3.connect(tmp_path / "cve.db")
    assert con.execute("SELECT count(*) FROM kev").fetchone() == (1,)


def test_refuses_to_overwrite(tmp_path):
    db = tmp_path / "cve.db"
    db.write_text("old")
    with pytest.raises(FileExistsError):
        write_db(db, [], [])


def test_text_index_holds_searchable_advisories_only(tmp_path):
    db = tmp_path / "cve.db"
    write_db(db, [adv(summary="Debugger PIN randomness", details="too little entropy"),
                  adv(id="MAL-1", summary="Malicious debugger")], [])
    con = sqlite3.connect(db)
    hits = con.execute("SELECT id FROM advisory_text WHERE advisory_text MATCH 'debugger'").fetchall()
    assert hits == [("GHSA-1",)]   # malware is not searchable, as in the Chroma index (D11)
    # Porter stemming: "pins" finds "PIN".
    assert con.execute("SELECT id FROM advisory_text WHERE advisory_text MATCH 'pins'").fetchall() == [
        ("GHSA-1",)]
