"""Match pinned requirements against the advisory database (spec 5.2). No AI here."""
from collections import defaultdict
from contextlib import closing
from pathlib import Path

from .db import kev_ids, load_records, open_db
from .matching import in_range, is_affected, lowest_above, parse_version, range_notes, read_bound
from .models import Finding, Pin, Record, ScanReport, Upgrade
from .requirements import parse_requirements

_ID_RANK = {"GHSA": 0, "PYSEC": 1}   # which ID to show first when a bug has several


def group_records(records: list[Record]) -> list[list[Record]]:
    """Records that share any ID or alias describe the same bug (e.g. GHSA + PYSEC)."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for rec in records:
        for alias in rec.aliases:
            parent[find(alias)] = find(rec.id)
    groups: dict[str, list[Record]] = defaultdict(list)
    for rec in records:
        groups[find(rec.id)].append(rec)
    return sorted(groups.values(), key=lambda g: min(r.id for r in g))


def _main_id(ids: list[str]) -> str:
    return min(ids, key=lambda i: (_ID_RANK.get(i.split("-")[0], 9), i))


def _fixes(records: list[Record]) -> set[str]:
    """Fixed versions as usable version strings (salvaged when not PEP 440)."""
    return {b for r in records for rng in r.ranges if rng.fixed and (b := read_bound(rng.fixed))}


def _notes(v, matched: list[Record]) -> tuple[str, ...]:
    """Notes for bad bounds in the ranges that made this version match."""
    notes = [n for r in matched for rng in r.ranges if in_range(v, rng) for n in range_notes(r.id, rng)]
    return tuple(dict.fromkeys(notes))


def _finding(pin: Pin, group: list[Record], kev: set[str]) -> Finding | None:
    v = parse_version(pin.version)
    matched = [r for r in group if is_affected(v, r.ranges, r.versions)]
    if not matched:
        return None
    main_id = _main_id([r.id for r in matched])
    all_ids = {r.id for r in group} | {a for r in group for a in r.aliases}
    main = next(r for r in matched if r.id == main_id)
    scores = [r.cvss_score for r in group if r.cvss_score is not None]
    fixed = _fixes(matched)
    return Finding(
        package=pin.name,
        version=pin.version,
        advisory_id=main_id,
        aliases=tuple(sorted(all_ids - {main_id})),
        records=tuple(sorted(r.id for r in matched)),
        summary=main.summary or next((r.summary for r in group if r.summary), ""),
        cvss_score=max(scores) if scores else None,
        in_kev=bool(all_ids & kev),
        is_malware=any(i.startswith("MAL-") for i in all_ids),
        fixed_versions=tuple(sorted(fixed, key=parse_version)),
        upgrade_to=lowest_above(v, fixed),
        notes=_notes(v, matched),
    )


def _affecting(v, groups: list[list[Record]]) -> tuple[str, ...]:
    """Main IDs of the advisory groups that affect version v, sorted."""
    return tuple(sorted(_main_id(hit) for g in groups
                        if (hit := [r.id for r in g if is_affected(v, r.ranges, r.versions)])))


def safe_upgrade(version: str, records: list[Record]) -> Upgrade:
    """The known fixed version above `version` hit by the fewest of the package's advisories
    (ties: final releases first, then lowest), and what still affects it."""
    v = parse_version(version)
    groups = group_records(records)
    candidates = [(pv, f) for f in _fixes(records) if (pv := parse_version(f)) > v]
    if not candidates:
        return Upgrade(None, _affecting(v, groups))
    scored = [(len(still := _affecting(pv, groups)), pv.is_prerelease, pv, f, still)
              for pv, f in candidates]
    *_, best, still = min(scored)
    return Upgrade(best, still)


def _sort_key(f: Finding):
    return (not f.is_malware, not f.in_kev, -(f.cvss_score or 0.0), f.package, f.advisory_id)


def scan(text: str, db_path: Path) -> ScanReport:
    parsed = parse_requirements(text)
    findings: list[Finding] = []
    upgrades: dict[str, Upgrade] = {}
    with closing(open_db(db_path)) as con:
        for pin in parsed.pins:
            records = load_records(con, pin.name)
            kev = kev_ids(con, {i for r in records for i in (r.id, *r.aliases)})
            found = [f for g in group_records(records) if (f := _finding(pin, g, kev))]
            if found:
                findings += found
                upgrades[pin.name] = safe_upgrade(pin.version, records)
    findings.sort(key=_sort_key)
    return ScanReport(findings, parsed.pins, parsed.not_pinned, parsed.skipped, upgrades)
