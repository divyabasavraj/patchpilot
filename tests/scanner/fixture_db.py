"""A tiny advisory DB with hand-checked answers, built with the real ingest writer."""
from pathlib import Path

from cve_copilot.ingest.models import Advisory, AffectedRange, KevEntry
from cve_copilot.ingest.store import write_db


def _adv(id, package, ranges=(), versions=(), aliases=(), score=None, summary=""):
    return Advisory(
        id=id, summary=summary or f"summary of {id}", details="", published=None, modified=None,
        cvss_vector=None, cvss_score=score, aliases=list(aliases),
        ranges=[AffectedRange(package, *rng) for rng in ranges],
        versions=[(package, v) for v in versions], refs=[])


ADVISORIES = [
    # Same bug stored twice (GHSA + PYSEC). Two ranges: two release branches.
    _adv("GHSA-flask-1", "flask", [("0", "2.2.5", None), ("2.3.0", "2.3.2", None)],
         aliases=["CVE-2023-1", "PYSEC-2023-1"], score=7.5),
    _adv("PYSEC-2023-1", "flask", [("0", "2.2.5", None), ("2.3.0", "2.3.2", None)],
         aliases=["CVE-2023-1", "GHSA-flask-1"], summary=" "),
    # A second flask bug, fixed later: its range covers 2.2.5 and 2.3.2.
    _adv("GHSA-flask-2", "flask", [("0", "3.1.3", None)], aliases=["CVE-2026-2"], score=5.0),
    # Django: one KEV-listed bug with a low score, one high-score bug not in KEV.
    _adv("GHSA-dj-1", "django", [("0", "4.2.1", None)], aliases=["CVE-2024-9"], score=5.0),
    _adv("GHSA-dj-2", "django", [("0", "4.2.2", None)], aliases=["CVE-2024-10"], score=9.8),
    # Malware: every version, no fix.
    _adv("MAL-2024-1", "reqeusts", [("0", None, None)]),
    # last_affected, explicit versions only, and a broken version string from the data.
    _adv("GHSA-old-1", "oldlib", [("1.0", None, "1.4")], score=4.0),
    _adv("GHSA-git-1", "gitlib", versions=["0.9", "1.0"], score=6.0),
    _adv("GHSA-bad-1", "badlib", [("2.6.0-cu124", "2.7", None), ("0", "1.0", None)], score=3.0),
    # Malware also published as a GHSA: the group's main ID is the GHSA (real case: litellm).
    _adv("GHSA-evil-1", "evilpkg", [("0", None, None)], score=9.0),
    _adv("MAL-2025-9", "evilpkg", [("0", None, None)], aliases=["GHSA-evil-1"]),
    # Same bug, but the two copies disagree on the fix: only PYSEC covers 1.5.
    _adv("GHSA-one-1", "onelib", [("0", "1.0", None)], aliases=["PYSEC-one-1"], score=6.5),
    _adv("PYSEC-one-1", "onelib", [("0", "2.0", None)], aliases=["GHSA-one-1"]),
    # Only bound is not PEP 440 (real example: pynetbox PYSEC-2024-325).
    _adv("PYSEC-net-1", "netlib", [("0", None, "4.1.0-NA")], score=5.5),
]
KEV = [KevEntry("CVE-2024-9", "2024-05-01", "Unknown")]


def build_fixture_db(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_db(path, ADVISORIES, KEV)
    return path
