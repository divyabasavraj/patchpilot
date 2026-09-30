from packaging.version import Version

from cve_copilot.ingest.models import AffectedRange
from cve_copilot.scanner.matching import (in_range, is_affected, lowest_above, parse_version,
                                          range_notes, read_bound)


def r(introduced="0", fixed=None, last_affected=None):
    return AffectedRange("pkg", introduced, fixed, last_affected)


V = Version


def test_fixed_is_exclusive_introduced_is_inclusive():
    rng = r("1.0", fixed="1.5")
    assert not in_range(V("0.9"), rng)
    assert in_range(V("1.0"), rng)
    assert in_range(V("1.4.9"), rng)
    assert not in_range(V("1.5"), rng)


def test_last_affected_is_inclusive():
    rng = r("1.0", last_affected="1.4")
    assert in_range(V("1.4"), rng)
    assert not in_range(V("1.4.1"), rng)


def test_open_range_affects_everything_after_introduced():
    assert in_range(V("99.0"), r("2.0"))
    assert not in_range(V("1.9"), r("2.0"))


def test_introduced_zero_means_from_the_start():
    assert in_range(V("0.0.1"), r("0", fixed="1.0"))


def test_prerelease_ordering():
    assert in_range(V("2.3.0rc1"), r("0", fixed="2.3.0"))       # rc1 comes before 2.3.0
    assert not in_range(V("2.3.0rc1"), r("2.3.0", fixed="2.3.2"))


def test_read_bound_salvages_the_leading_release_number():
    assert read_bound("1.2.3") == "1.2.3"
    assert read_bound("4.1.0-NA") == "4.1.0"
    assert read_bound("2.6.0-cu124") == "2.6.0"
    assert read_bound("0.9-stable") == "0.9"
    assert read_bound("1.6.5ubuntu0.1") == "1.6.5"
    assert read_bound(" v2.0-beta_x") == "2.0"
    assert read_bound("unknown") is None
    assert read_bound("") is None


def test_unparseable_range_values_are_salvaged_not_dropped():
    assert in_range(V("2.6.0"), r("2.6.0-cu124", fixed="2.7"))
    assert not in_range(V("2.5.9"), r("2.6.0-cu124", fixed="2.7"))
    assert not in_range(V("1.0"), r("0", fixed="0.14.0-NA"))      # read as fixed in 0.14.0
    assert in_range(V("0.13"), r("0", fixed="0.14.0-NA"))
    assert in_range(V("4.0.0"), r("0", last_affected="4.1.0-NA"))
    assert in_range(V("4.1.0"), r("0", last_affected="4.1.0-NA"))
    assert not in_range(V("4.1.1"), r("0", last_affected="4.1.0-NA"))
    assert in_range(V("0.9"), r("0", last_affected="0.9-stable"))


def test_bounds_with_no_number_over_report():
    assert in_range(V("0.1"), r("garbage", fixed="2.0"))            # introduced read as 0
    assert in_range(V("99.0"), r("0", fixed="unknown"))             # treated as not fixed
    assert in_range(V("99.0"), r("0", last_affected="n/a"))


def test_range_notes_describe_each_bad_bound():
    assert range_notes("A-1", r("0", fixed="1.0")) == []
    assert range_notes("PYSEC-2024-325", r("0", last_affected="4.1.0-NA")) == [
        "PYSEC-2024-325: advisory version '4.1.0-NA' is not a valid version; read as 4.1.0"]
    assert range_notes("A-1", r("garbage", fixed="unknown")) == [
        "A-1: advisory version 'garbage' is not a valid version; read as 0",
        "A-1: advisory version 'unknown' is not a valid version; treated as not fixed"]


def test_explicit_versions_compare_as_versions():
    assert is_affected(V("1.0.0"), [], ["0.9", "1.0"])           # 1.0 == 1.0.0 in PEP 440
    assert not is_affected(V("1.1"), [], ["0.9", "1.0", "0.1-bulbasaur"])


def test_is_affected_checks_every_range():
    ranges = [r("0", fixed="2.2.5"), r("2.3.0", fixed="2.3.2")]
    assert is_affected(V("2.3.1"), ranges, [])
    assert not is_affected(V("2.2.5"), ranges, [])


def test_lowest_above():
    assert lowest_above(V("2.2.0"), ["2.3.2", "2.2.5", "bad-version", "2.2.0"]) == "2.2.5"
    assert lowest_above(V("3.0"), ["2.2.5"]) is None
    assert lowest_above(V("2.0"), ["2.6.0-cu124"]) == "2.6.0"          # salvaged fix is offered


def test_parse_version():
    assert parse_version("1.0") == V("1.0")
    assert parse_version("0.1-bulbasaur") is None
