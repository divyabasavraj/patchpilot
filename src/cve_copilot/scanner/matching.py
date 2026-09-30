"""Is one installed version affected? Pure functions, no database."""
import re
from collections.abc import Iterable
from functools import lru_cache

from packaging.version import InvalidVersion, Version

from ..ingest.models import AffectedRange

_LEADING_RELEASE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)")   # "4.1.0-NA" -> "4.1.0"


@lru_cache(maxsize=65536)
def parse_version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


@lru_cache(maxsize=65536)
def read_bound(text: str) -> str | None:
    """A range bound as a usable version string: as written if valid, else its leading
    release number ("2.6.0-cu124" -> "2.6.0"), else None (no number to salvage)."""
    if parse_version(text) is not None:
        return text
    m = _LEADING_RELEASE.match(text)
    return m.group(1) if m else None


def _bound(text: str | None) -> Version | None:
    read = read_bound(text) if text is not None else None
    return parse_version(read) if read is not None else None


def in_range(v: Version, r: AffectedRange) -> bool:
    """OSV ECOSYSTEM range: introduced <= v < fixed, or introduced <= v <= last_affected.
    Bounds that are not valid versions are salvaged (see read_bound); with nothing to
    salvage, `introduced` counts as 0 and `fixed`/`last_affected` as "no end" (over-report)."""
    start = _bound(r.introduced)
    if start is not None and v < start:
        return False
    if r.fixed is not None and (end := _bound(r.fixed)) is not None:
        return v < end
    if r.last_affected is not None and (end := _bound(r.last_affected)) is not None:
        return v <= end
    return True


def range_notes(advisory_id: str, r: AffectedRange) -> list[str]:
    """One human-readable note per bound of `r` that is not a valid version."""
    notes = []
    for text, fallback in ((r.introduced, "read as 0"), (r.fixed, "treated as not fixed"),
                           (r.last_affected, "treated as not fixed")):
        if text is None or parse_version(text) is not None:
            continue
        read = read_bound(text)
        how = f"read as {read}" if read is not None else fallback
        notes.append(f"{advisory_id}: advisory version '{text}' is not a valid version; {how}")
    return notes


def is_affected(v: Version, ranges: Iterable[AffectedRange], versions: Iterable[str]) -> bool:
    return any(in_range(v, r) for r in ranges) or any(parse_version(x) == v for x in versions)


def lowest_above(v: Version, candidates: Iterable[str]) -> str | None:
    """Lowest candidate above v; candidates that are not versions are salvaged or dropped."""
    usable = {b for c in candidates if (b := read_bound(c)) is not None}
    above = [(pv, b) for b in usable if (pv := parse_version(b)) > v]
    return min(above)[1] if above else None
