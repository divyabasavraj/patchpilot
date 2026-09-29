import pytest

from cve_copilot.scanner import scan
from cve_copilot.ingest.models import AffectedRange
from cve_copilot.scanner.models import Record, Upgrade
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
    assert scan("flask==2.2.0\n", db).upgrades == {"flask": Upgrade("3.1.3", ())}


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
    assert report.upgrades == {"reqeusts": Upgrade(None, ("MAL-2024-1",))}


def test_last_affected_and_versions_only(db):
    assert ids(scan("oldlib==1.4\n", db)) == ["GHSA-old-1"]
    assert ids(scan("oldlib==1.4.1\n", db)) == []
    assert ids(scan("gitlib==1.0.0\n", db)) == ["GHSA-git-1"]
    assert scan("oldlib==1.4\n", db).findings[0].upgrade_to is None


def test_bad_version_in_db_does_not_crash(db):
    [f] = scan("badlib==2.6.5\n", db).findings               # "2.6.0-cu124" read as 2.6.0
    assert f.advisory_id == "GHSA-bad-1" and f.upgrade_to == "2.7"
    assert f.notes == ("GHSA-bad-1: advisory version '2.6.0-cu124' is not a valid version; read as 2.6.0",)
    [f] = scan("badlib==0.5\n", db).findings                 # the valid range still works
    assert f.advisory_id == "GHSA-bad-1" and f.notes == ()
    assert ids(scan("badlib==2.5\n", db)) == []


def test_last_affected_that_is_not_a_version_still_matches(db):
    [f] = scan("netlib==4.0.0\n", db).findings
    assert f.advisory_id == "PYSEC-net-1"
    assert f.notes == ("PYSEC-net-1: advisory version '4.1.0-NA' is not a valid version; read as 4.1.0",)
    assert ids(scan("netlib==4.1.1\n", db)) == []


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


def rec(id, *ranges, aliases=()):
    return Record(id, aliases, "", None, tuple(AffectedRange("x", *r) for r in ranges), ())


def test_safe_upgrade_none_when_no_fix():
    assert safe_upgrade("1.0", [rec("MAL-1", ("0", None, None))]) == Upgrade(None, ("MAL-1",))


def test_upgrade_still_offered_when_an_unfixed_advisory_remains(db):
    assert scan("mixlib==1.0\n", db).upgrades == {"mixlib": Upgrade("1.5", ("GHSA-mix-2",))}


def test_upgrade_picks_the_candidate_hit_by_fewest_advisories():
    records = [rec("GHSA-a", ("0", "2.0", None)),       # fixed in 2.0
               rec("GHSA-b", ("0", "1.1", None)),       # fixed in 1.1 ...
               rec("GHSA-c", ("2.0", "2.1", None))]     # ... but 2.0 brings a new bug
    assert safe_upgrade("1.0", records) == Upgrade("2.1", ())
    records.append(rec("GHSA-d", ("0", None, None)))   # never fixed: every candidate keeps it
    assert safe_upgrade("1.0", records) == Upgrade("2.1", ("GHSA-d",))


def test_upgrade_ties_prefer_final_releases_then_lowest():
    # GHSA-b is on another branch (3.0 up to 3.1), so its fix is a candidate too and both clear everything.
    assert safe_upgrade("1.0", [rec("GHSA-a", ("0", "2.0rc1", None)),
                                rec("GHSA-b", ("3.0", "3.1", None))]) == Upgrade("3.1", ())
    assert safe_upgrade("1.0", [rec("GHSA-a", ("0", "1.5", None)),
                                rec("GHSA-b", ("3.0", "3.1", None))]) == Upgrade("1.5", ())


def test_upgrade_still_affected_uses_the_main_id():
    records = [rec("PYSEC-1", ("0", None, None), aliases=("GHSA-1",)),
               rec("GHSA-1", ("0", None, None), aliases=("PYSEC-1",)),
               rec("GHSA-2", ("0", "3.0", None))]
    assert safe_upgrade("1.0", records) == Upgrade("3.0", ("GHSA-1",))


def test_malware_flag_survives_grouping_with_a_ghsa(db):
    report = scan("django==4.0\nevilpkg==1.0\n", db)
    f = report.findings[0]
    assert f.advisory_id == "GHSA-evil-1" and f.records == ("GHSA-evil-1", "MAL-2025-9")
    assert f.is_malware and not f.in_kev                  # sorted before the KEV django finding
    assert not any(g.is_malware for g in report.findings[1:])


def test_group_where_only_one_copy_matches(db):
    [f] = scan("onelib==1.5\n", db).findings
    assert f.advisory_id == "PYSEC-one-1" and f.records == ("PYSEC-one-1",)
    assert f.aliases == ("GHSA-one-1",)
    assert f.cvss_score == 6.5 and f.upgrade_to == "2.0" and not f.is_malware
    [f] = scan("onelib==0.5\n", db).findings
    assert f.advisory_id == "GHSA-one-1" and f.records == ("GHSA-one-1", "PYSEC-one-1")
