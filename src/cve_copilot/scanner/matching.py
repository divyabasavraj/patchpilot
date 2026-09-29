"""Is one installed version affected? Pure functions, no database."""
from collections.abc import Iterable
from functools import lru_cache

from packaging.version import InvalidVersion, Version

from ..ingest.models import AffectedRange


@lru_cache(maxsize=65536)
def parse_version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def in_range(v: Version, r: AffectedRange) -> bool:
    """OSV ECOSYSTEM range: introduced <= v < fixed, or introduced <= v <= last_affected.
    A range containing a value that is not a valid version is ignored."""
    start = parse_version(r.introduced or "0")
    if start is None or v < start:
        return False
    if r.fixed is not None:
        end = parse_version(r.fixed)
        return end is not None and v < end
    if r.last_affected is not None:
        end = parse_version(r.last_affected)
        return end is not None and v <= end
    return True


def is_affected(v: Version, ranges: Iterable[AffectedRange], versions: Iterable[str]) -> bool:
    return any(in_range(v, r) for r in ranges) or any(parse_version(x) == v for x in versions)


def lowest_above(v: Version, candidates: Iterable[str]) -> str | None:
    above = [(pv, c) for c in candidates if (pv := parse_version(c)) is not None and pv > v]
    return min(above)[1] if above else None
