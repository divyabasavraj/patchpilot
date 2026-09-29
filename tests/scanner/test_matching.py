from packaging.version import Version

from cve_copilot.ingest.models import AffectedRange
from cve_copilot.scanner.matching import in_range, is_affected, lowest_above, parse_version


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


def test_unparseable_range_values_are_ignored():
    assert not in_range(V("2.6.0"), r("2.6.0-cu124", fixed="2.7"))
    assert not in_range(V("1.0"), r("0", fixed="0.14.0-NA"))
    assert not in_range(V("1.0"), r("0", last_affected="0.9-stable"))


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


def test_parse_version():
    assert parse_version("1.0") == V("1.0")
    assert parse_version("0.1-bulbasaur") is None
