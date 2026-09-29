"""Data objects the scanner reads and returns."""
from dataclasses import dataclass, field

from ..ingest.models import AffectedRange


@dataclass(frozen=True)
class Pin:
    name: str        # canonical package name
    version: str     # as written in the file
    line_no: int
    line: str        # the requirement without comments or --hash options


@dataclass(frozen=True)
class LineNote:
    line_no: int
    line: str
    reason: str


@dataclass
class ParsedRequirements:
    pins: list[Pin] = field(default_factory=list)
    not_pinned: list[LineNote] = field(default_factory=list)
    skipped: list[LineNote] = field(default_factory=list)


@dataclass(frozen=True)
class Record:
    """One stored advisory's data for one package."""
    id: str
    aliases: tuple[str, ...]
    summary: str
    cvss_score: float | None
    ranges: tuple[AffectedRange, ...]
    versions: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    package: str
    version: str
    advisory_id: str                 # main ID: GHSA, then PYSEC, then others
    aliases: tuple[str, ...]         # every other ID for the same bug (CVE, GHSA, PYSEC...)
    records: tuple[str, ...]         # stored advisories whose own data matched this version
    summary: str
    cvss_score: float | None
    in_kev: bool
    is_malware: bool                 # any ID or alias in the group is a MAL- (malicious package) ID
    fixed_versions: tuple[str, ...]  # oldest first
    upgrade_to: str | None           # lowest fixed version above the installed one
    notes: tuple[str, ...] = ()      # caveats, e.g. a range bound that is not a valid version


@dataclass(frozen=True)
class Upgrade:
    """Suggested version for one vulnerable package."""
    version: str | None               # None: no fixed version known
    still_affected: tuple[str, ...]   # main IDs of advisories that still affect `version`


@dataclass
class ScanReport:
    findings: list[Finding]
    checked: list[Pin]
    not_pinned: list[LineNote]
    skipped: list[LineNote]
    upgrades: dict[str, Upgrade]     # vulnerable package -> suggested upgrade
