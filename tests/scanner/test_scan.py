import pytest

from cve_copilot.scanner import scan
from cve_copilot.scanner.models import Record
from cve_copilot.scanner.scan import group_records, safe_upgrade
from tests.scanner.fixture_db import build_fixture_db


@pytest.fixture
def db(tmp_path):
    return build_fixture_db(tmp_path / "cve.db")


def ids(report):
    return [f.advisory_id for f in report.findings]


def test_ghsa_and_pysec_duplicates_become_one_finding(db):
    report = scan("flask==2.2.0\n", db)
    assert ids(report) == ["GHSA-flask-1", "GHSA-flask-2"]
    f = report.findings[0]
    assert f.records == ("GHSA-flask-1", "PYSEC-2023-1")
    assert f.aliases == ("CVE-2023-1", "PYSEC-2023-1")
    assert f.cvss_score == 7.5                       # PYSEC copy has no score; the group's best is used
    assert f.summary == "summary of GHSA-flask-1"
    assert f.fixed_versions == ("2.2.5", "2.3.2")
    assert f.upgrade_to == "2.2.5"
    assert f.package == "flask" and f.version == "2.2.0" and not f.in_kev


def test_upgrade_on_the_second_branch(db):
    f = scan("flask==2.3.0\n", db).findings[0]
    assert f.advisory_id == "GHSA-flask-1" and f.upgrade_to == "2.3.2"


def test_safe_upgrade_skips_versions_hit_by_other_advisories(db):
    assert scan("flask==2.2.0\n", db).upgrades == {"flask": "3.1.3"}


def test_fixed_version_has_no_findings(db):
    report = scan("flask==3.1.3\n", db)
    assert report.findings == [] and report.upgrades == {}
    assert [p.name for p in report.checked] == ["flask"]


def test_prerelease_pin(db):
    # 2.3.0rc1 is after 2.2.5 and before 2.3.0: outside both flask-1 ranges, inside flask-2.
    assert ids(scan("flask==2.3.0rc1\n", db)) == ["GHSA-flask-2"]


def test_sort_malware_then_kev_then_cvss(db):
    report = scan("django==4.0\nreqeusts==1.0\n", db)
    assert ids(report) == ["MAL-2024-1", "GHSA-dj-1", "GHSA-dj-2"]
    assert report.findings[0].is_malware
    assert report.findings[1].in_kev and not report.findings[2].in_kev


def test_no_fix_known(db):
    report = scan("reqeusts==1.0\n", db)
    assert report.findings[0].upgrade_to is None
    assert report.upgrades == {"reqeusts": None}


def test_last_affected_and_versions_only(db):
    assert ids(scan("oldlib==1.4\n", db)) == ["GHSA-old-1"]
    assert ids(scan("oldlib==1.4.1\n", db)) == []
    assert ids(scan("gitlib==1.0.0\n", db)) == ["GHSA-git-1"]
    assert scan("oldlib==1.4\n", db).findings[0].upgrade_to is None


def test_bad_version_in_db_does_not_crash(db):
    assert ids(scan("badlib==2.6.5\n", db)) == []             # broken range ignored
    assert ids(scan("badlib==0.5\n", db)) == ["GHSA-bad-1"]   # the valid range still works


def test_unknown_package_and_line_notes_pass_through(db):
    report = scan("some-unknown-pkg==1.0\nflask\n-r base.txt\n", db)
    assert report.findings == []
    assert [n.line_no for n in report.not_pinned] == [2]
    assert [n.line_no for n in report.skipped] == [3]


def test_group_records_links_through_shared_aliases():
    a = Record("GHSA-a", ("CVE-1",), "", None, (), ())
    b = Record("PYSEC-b", ("CVE-1",), "", None, (), ())     # linked only through the CVE
    c = Record("GHSA-c", (), "", None, (), ())
    assert [[r.id for r in g] for g in group_records([a, b, c])] == [["GHSA-a", "PYSEC-b"], ["GHSA-c"]]


def test_safe_upgrade_none_when_no_fix():
    from cve_copilot.ingest.models import AffectedRange
    rec = Record("MAL-1", (), "", None, (AffectedRange("x", "0", None, None),), ())
    assert safe_upgrade("1.0", [rec]) is None
