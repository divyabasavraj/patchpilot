import sqlite3

import pytest

from cve_copilot.ingest.models import AffectedRange
from cve_copilot.scanner.db import kev_ids, load_records, open_db
from tests.scanner.fixture_db import build_fixture_db


@pytest.fixture
def con(tmp_path):
    c = open_db(build_fixture_db(tmp_path / "cve.db"))
    yield c
    c.close()


def test_load_records_for_a_package(con):
    records = load_records(con, "flask")
    assert [r.id for r in records] == ["GHSA-flask-1", "GHSA-flask-2", "PYSEC-2023-1"]
    first = records[0]
    assert first.aliases == ("CVE-2023-1", "PYSEC-2023-1")
    assert first.cvss_score == 7.5
    assert first.summary == "summary of GHSA-flask-1"
    assert first.ranges == (AffectedRange("flask", "0", "2.2.5", None),
                            AffectedRange("flask", "2.3.0", "2.3.2", None))


def test_versions_only_record(con):
    [rec] = load_records(con, "gitlib")
    assert rec.ranges == () and sorted(rec.versions) == ["0.9", "1.0"]


def test_unknown_package_gives_nothing(con):
    assert load_records(con, "not-a-package") == []


def test_kev_ids(con):
    assert kev_ids(con, ["CVE-2024-9", "CVE-2024-10", "GHSA-dj-1"]) == {"CVE-2024-9"}
    assert kev_ids(con, []) == set()


def test_database_is_opened_read_only(con):
    with pytest.raises(sqlite3.OperationalError):
        con.execute("DELETE FROM kev")


def test_missing_db_has_clear_message(tmp_path):
    with pytest.raises(FileNotFoundError, match="Build it first"):
        open_db(tmp_path / "nope" / "cve.db")
