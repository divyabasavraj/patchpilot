import pytest

from cve_copilot.ingest.models import AffectedRange
from cve_copilot.ingest.osv import parse_osv


def record(**overrides):
    base = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "summary": "SQL injection in Django",
        "details": "Long details.",
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-01-02T00:00:00Z",
        "aliases": ["CVE-2024-0001", "PYSEC-2024-1"],
        "affected": [{
            "package": {"name": "Django", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "3.0"}, {"fixed": "3.2.5"}]}],
            "versions": ["3.0", "3.1"],
        }],
        "references": [{"type": "ADVISORY", "url": "https://example.com/a"}],
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    }
    base.update(overrides)
    return base


def test_basic_fields():
    adv = parse_osv(record())
    assert adv.id == "GHSA-aaaa-bbbb-cccc"
    assert adv.summary == "SQL injection in Django"
    assert adv.aliases == ["CVE-2024-0001", "PYSEC-2024-1"]
    assert adv.refs == [("ADVISORY", "https://example.com/a")]
    assert adv.cvss_score == 7.5
    assert adv.cvss_vector.startswith("CVSS:3.1/")


def test_package_name_is_canonical():
    adv = parse_osv(record())
    assert adv.ranges == [AffectedRange("django", "3.0", "3.2.5", None)]
    assert adv.versions == [("django", "3.0"), ("django", "3.1")]
    assert adv.packages == ["django"]


def test_withdrawn_returns_none():
    assert parse_osv(record(withdrawn="2024-02-01T00:00:00Z")) is None


def test_missing_id_is_malformed():
    rec = record()
    del rec["id"]
    with pytest.raises(ValueError):
        parse_osv(rec)


def test_multiple_ranges_and_last_affected():
    rec = record(affected=[{
        "package": {"name": "pkg", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.0"},
            {"introduced": "2.0"}, {"last_affected": "2.4"},
            {"introduced": "3.0"},
        ]}],
    }])
    assert parse_osv(rec).ranges == [
        AffectedRange("pkg", "0", "1.0", None),
        AffectedRange("pkg", "2.0", None, "2.4"),
        AffectedRange("pkg", "3.0", None, None),   # no fix yet
    ]


def test_non_pypi_packages_are_ignored():
    rec = record(affected=[
        {"package": {"name": "django", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1"}]}]},
        {"package": {"name": "left-pad", "ecosystem": "npm"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2"}]}],
         "versions": ["1.0.0"]},
    ])
    adv = parse_osv(rec)
    assert adv.packages == ["django"]


def test_git_only_ranges_keep_explicit_versions():
    rec = record(affected=[{
        "package": {"name": "thumbor", "ecosystem": "PyPI"},
        "ranges": [{"type": "GIT", "repo": "https://github.com/x/y",
                    "events": [{"introduced": "abc123"}, {"fixed": "def456"}]}],
        "versions": ["6.0.0"],
    }])
    adv = parse_osv(rec)
    assert adv.ranges == []
    assert adv.versions == [("thumbor", "6.0.0")]


def test_cvss_prefers_v3_over_v4():
    rec = record(severity=[
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    ])
    assert parse_osv(rec).cvss_score == 7.5


def test_cvss_v4_only():
    rec = record(severity=[{"type": "CVSS_V4",
                            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}])
    assert parse_osv(rec).cvss_score == 8.7


def test_no_or_bad_severity_gives_none():
    assert parse_osv(record(severity=[])).cvss_score is None
    bad = parse_osv(record(severity=[{"type": "CVSS_V3", "score": "garbage"}]))
    assert bad.cvss_score is None
    assert bad.cvss_vector == "garbage"


def test_missing_optional_fields_default_to_empty():
    rec = {"id": "PYSEC-2020-1", "affected": []}
    adv = parse_osv(rec)
    assert adv.summary == "" and adv.details == ""
    assert adv.aliases == [] and adv.refs == [] and adv.ranges == []


def test_bad_v3_falls_back_to_valid_v4():
    rec = record(severity=[
        {"type": "CVSS_V3", "score": "garbage"},
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
    ])
    assert parse_osv(rec).cvss_score == 8.7


def test_null_summary_and_details_become_empty():
    adv = parse_osv(record(summary=None, details=None))
    assert adv.summary == "" and adv.details == ""
