"""Plain data objects shared by the ingest steps."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AffectedRange:
    package: str                # canonical name
    introduced: str | None
    fixed: str | None
    last_affected: str | None


@dataclass
class Advisory:
    id: str
    summary: str
    details: str
    published: str | None
    modified: str | None
    cvss_vector: str | None
    cvss_score: float | None
    aliases: list[str] = field(default_factory=list)
    ranges: list[AffectedRange] = field(default_factory=list)
    versions: list[tuple[str, str]] = field(default_factory=list)   # (package, version)
    refs: list[tuple[str, str]] = field(default_factory=list)       # (type, url)
    flagged: bool = False
    flag_reason: str | None = None

    @property
    def packages(self) -> list[str]:
        names = {r.package for r in self.ranges} | {p for p, _ in self.versions}
        return sorted(names)


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: str
    ransomware: str
