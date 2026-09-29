# Phase 2: Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read a `requirements.txt`, check every pinned package against the advisory database built in Phase 1, and return a sorted list of findings (advisory, CVSS, KEV, fixed versions, suggested upgrade), plus the lines that were not checked. No AI anywhere in this phase. Also build the `scan_cases` exam and measure scanner accuracy.

**Architecture:** A new package `src/cve_copilot/scanner/` with small modules: `requirements.py` turns text into pins and line notes; `matching.py` answers "is version X inside this OSV range?" with pure functions; `db.py` reads one package's advisories from SQLite (read-only); `scan.py` groups duplicate advisories (GHSA + PYSEC for the same bug), builds `Finding`s, sorts them, and picks upgrades. A CLI (`python -m cve_copilot.scanner FILE`) prints a table. The exam (`evals/scan_exam.py`) runs the scanner on `evals/data/scan_cases.jsonl`, whose expected answers come from the OSV.dev API, not from our own code.

**Tech Stack:** Python 3.12 (uv), `packaging` (requirements, versions, names), `sqlite3`, httpx (only in the one-off exam generator), pytest.

**Spec:** `docs/superpowers/specs/2026-09-26-cve-copilot-design.md` (sections 2, 5.2, 7, 8, 9, 11)

## Global Constraints

- Python 3.12, managed with `uv`. Run everything with `uv run ...`.
- Plain Python modules only; no LangChain or LlamaIndex.
- **Facts come from code.** The scanner never calls an LLM.
- Unit tests make no network calls. Only `evals/make_scan_cases.py` touches the network, and it is run once by hand.
- Package names are always canonicalised with `packaging.utils.canonicalize_name`.
- Versions are compared with `packaging.version.Version` (PEP 440), never as strings.
- `name==version` lines are checked. Unpinned lines or ranges (`>=`, `~=`, no version, `==2.*`) are reported as **not checked: not pinned**. `-r`, `-e`, other pip options, URLs, VCS lines and local paths are reported as **skipped**. Nothing in a requirements file may crash the scanner.
- Affected if listed in `affected_versions`, or `introduced <= v < fixed`, or `introduced <= v <= last_affected` (spec 5.2).
- Scanner accuracy pass mark on the `scan_cases` exam: **100%**.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions made while planning (log as D15–D19)

Found by querying `data/live/cve.db` and the OSV API on 2026-09-29.

- **D15. Duplicate advisories are merged into one finding.** The OSV PyPI export stores most vulnerabilities twice, as a GitHub advisory (`GHSA-…`) and a PyPA one (`PYSEC-…`) that list each other as aliases: 16,990 alias rows point at another advisory in the DB. Flask 2.2.0 would otherwise show CVE-2023-30861 twice. Records that share any ID or alias form one group. The finding's main ID prefers `GHSA`, then `PYSEC`, then others, and `Finding.records` lists which stored advisories actually matched.
- **D16. Malware findings sort first, above KEV.** A `MAL-…` advisory means the package itself is malicious (usually a typo-squat like `reqeusts`). That is more urgent than any bug, and it has no CVSS score, so plain "KEV, then CVSS" sorting would put it last.
- **D17. Environment markers are not evaluated.** `pywin32==300; sys_platform == "win32"` is still checked. We don't know the user's platform, and a missed vulnerability is worse than one extra row.
- **D18. One safe upgrade per package.** Besides the per-finding `upgrade_to` (lowest fix above the installed version, from spec 5.2), the report gives, per vulnerable package, the lowest known fixed version that no known advisory affects. The per-finding fix for one bug can land inside another bug's range (tested in Task 4).
- **D19. The exam's expected answers come from the OSV.dev API.** If the expected answers were produced by our own scanner, the exam could never fail. `api.osv.dev/v1/querybatch` does its own version matching; the generator keeps only IDs present (and not withdrawn) in the frozen snapshot, so the answer key matches the frozen data.

Data facts the code must survive (live DB, 2026-09-29): 27 range values and 1,872 listed versions are not valid PEP 440 versions (e.g. `2.6.0-cu124`, `0.1-bulbasaur`); 18,164 ranges start at `introduced: "0"`; 5,430 advisories have only a `versions` list and no ranges.

## Review Focus

1. **`pip-compile` output** (`flask==2.2.0 \` followed by `--hash=sha256:…` lines and `# via` comments) must give a normal pin, not "could not parse". Tested in Task 1 (`test_pip_compile_hashes_and_continuations`).
2. **The same bug stored as GHSA and PYSEC** must appear as one finding, with both IDs visible. Tested in Task 4 (`test_ghsa_and_pysec_duplicates_become_one_finding`).
3. **Invalid version strings in the database** must be ignored for that range, never crash the scan. Tested in Task 2 (`test_unparseable_range_values_are_ignored`) and Task 4 (`test_bad_version_in_db_does_not_crash`).
4. **Pre-release pins** (`flask==2.3.0rc1`) must compare as PEP 440 says (`2.3.0rc1 < 2.3.0`). Tested in Task 2 (`test_prerelease_ordering`) and Task 4 (`test_prerelease_pin`).
5. **The suggested package upgrade must not point at a version another advisory still affects.** Tested in Task 4 (`test_safe_upgrade_skips_versions_hit_by_other_advisories`).
6. **No database yet** (fresh clone, ingest not run) must print "Build it first" and exit 2, not a traceback. Tested in Task 3 (`test_missing_db_has_clear_message`) and Task 5 (`test_cli_missing_db`).

---

## File map

| File | Responsibility |
|---|---|
| `src/cve_copilot/config.py` | Add `Settings.db_dir(target)` (shared by ingest CLI, scanner CLI, exam) |
| `src/cve_copilot/scanner/__init__.py` | Re-exports `scan`, `parse_requirements` |
| `src/cve_copilot/scanner/models.py` | `Pin`, `LineNote`, `ParsedRequirements`, `Record`, `Finding`, `ScanReport` |
| `src/cve_copilot/scanner/requirements.py` | `parse_requirements(text) -> ParsedRequirements` |
| `src/cve_copilot/scanner/matching.py` | `parse_version`, `in_range`, `is_affected`, `lowest_above` (pure) |
| `src/cve_copilot/scanner/db.py` | `open_db(path)`, `load_records(con, package)`, `kev_ids(con, ids)` |
| `src/cve_copilot/scanner/scan.py` | `group_records`, `safe_upgrade`, `scan(text, db_path) -> ScanReport` |
| `src/cve_copilot/scanner/__main__.py` | CLI and `format_report(report)` |
| `evals/make_scan_cases.py` | One-off: build expected answers from the OSV API |
| `evals/data/scan_cases.jsonl` | The exam (committed) |
| `evals/scan_exam.py` | `run(cases_path, db_path) -> dict`; CLI prints the score |
| `tests/scanner/fixture_db.py` | `build_fixture_db(path)`: a tiny DB with known answers |
| `tests/scanner/test_*.py`, `tests/evals/test_scan_exam.py` | One test file per module |

---

### Task 1: Branch, models and the requirements parser

**Files:**
- Create: `src/cve_copilot/scanner/__init__.py` (empty for now), `src/cve_copilot/scanner/models.py`, `src/cve_copilot/scanner/requirements.py`, `tests/scanner/__init__.py` (empty), `tests/scanner/test_requirements.py`

**Interfaces:**
- Consumes: nothing from Phase 1 except `cve_copilot.ingest.models.AffectedRange` (used in `Record`).
- Produces:
  - `Pin(name: str, version: str, line_no: int, line: str)`: frozen; `name` is canonical, `version` as written.
  - `LineNote(line_no: int, line: str, reason: str)`: frozen.
  - `ParsedRequirements(pins: list[Pin], not_pinned: list[LineNote], skipped: list[LineNote])`.
  - `Record(id, aliases: tuple[str, ...], summary: str, cvss_score: float | None, ranges: tuple[AffectedRange, ...], versions: tuple[str, ...])`: frozen.
  - `Finding(package, version, advisory_id, aliases, records, summary, cvss_score, in_kev, fixed_versions, upgrade_to)` + property `is_malware`.
  - `ScanReport(findings: list[Finding], checked: list[Pin], not_pinned: list[LineNote], skipped: list[LineNote], upgrades: dict[str, str | None])`.
  - `parse_requirements(text: str) -> ParsedRequirements`. `line_no` is the first physical line of a logical line (1-based).

- [ ] **Step 1: Create the branch**

```bash
cd cve-copilot
git checkout main && git checkout -b phase2-scanner
mkdir -p src/cve_copilot/scanner tests/scanner
touch src/cve_copilot/scanner/__init__.py tests/scanner/__init__.py
```

- [ ] **Step 2: Write the models**

`src/cve_copilot/scanner/models.py`:
```python
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
    fixed_versions: tuple[str, ...]  # oldest first
    upgrade_to: str | None           # lowest fixed version above the installed one

    @property
    def is_malware(self) -> bool:
        return self.advisory_id.startswith("MAL-")


@dataclass
class ScanReport:
    findings: list[Finding]
    checked: list[Pin]
    not_pinned: list[LineNote]
    skipped: list[LineNote]
    upgrades: dict[str, str | None]  # vulnerable package -> lowest version with no known advisory
```

- [ ] **Step 3: Write the failing parser tests**

`tests/scanner/test_requirements.py`:
```python
from cve_copilot.scanner.models import Pin
from cve_copilot.scanner.requirements import parse_requirements


def pins(text):
    return [(p.name, p.version, p.line_no) for p in parse_requirements(text).pins]


def notes(text, kind):
    return [(n.line_no, n.reason) for n in getattr(parse_requirements(text), kind)]


def test_simple_pins_with_canonical_names():
    text = "Django==4.2.0\nDjango_Rest.Framework==3.14.0\nflask == 2.2.0\n"
    assert pins(text) == [("django", "4.2.0", 1), ("django-rest-framework", "3.14.0", 2), ("flask", "2.2.0", 3)]


def test_pin_keeps_the_line_as_written():
    assert parse_requirements("flask==2.2.0  # web\n").pins == [Pin("flask", "2.2.0", 1, "flask==2.2.0")]


def test_comments_and_blank_lines_are_ignored():
    text = "# top comment\n\n   \nflask==2.2.0  # inline comment\n"
    parsed = parse_requirements(text)
    assert pins(text) == [("flask", "2.2.0", 4)]
    assert parsed.not_pinned == [] and parsed.skipped == []


def test_extras_and_markers_are_checked():
    text = "requests[socks]==2.19.0\npywin32==300; sys_platform == 'win32'\n"
    assert pins(text) == [("requests", "2.19.0", 1), ("pywin32", "300", 2)]


def test_unpinned_lines_are_reported():
    text = "flask\ndjango>=3,<4\nrequests~=2.0\nurllib3==1.*\nidna>=2,==2.8\n"
    assert pins(text) == []
    assert notes(text, "not_pinned") == [(1, "not pinned"), (2, "not pinned"), (3, "not pinned"),
                                         (4, "not pinned"), (5, "not pinned")]


def test_options_urls_and_paths_are_skipped():
    text = ("-r base.txt\n"
            "-e .\n"
            "--index-url https://pypi.org/simple\n"
            "git+https://github.com/psf/black.git\n"
            "pkg @ https://example.com/pkg-1.0.whl\n"
            "./local/pkg.whl\n"
            "!!! not a requirement\n")
    assert pins(text) == []
    assert notes(text, "skipped") == [
        (1, "pip option -r"), (2, "pip option -e"), (3, "pip option --index-url"),
        (4, "URL, VCS or local path"), (5, "URL, VCS or local path"), (6, "URL, VCS or local path"),
        (7, "could not parse")]


def test_pip_compile_hashes_and_continuations():
    text = ("flask==2.2.0 \\\n"
            "    --hash=sha256:aaaa \\\n"
            "    --hash=sha256:bbbb\n"
            "    # via -r requirements.in\n"
            "jinja2==3.1.2 \\\n"
            "    --hash=sha256:cccc\n")
    parsed = parse_requirements(text)
    assert pins(text) == [("flask", "2.2.0", 1), ("jinja2", "3.1.2", 5)]
    assert parsed.skipped == [] and parsed.not_pinned == []
    assert parsed.pins[0].line == "flask==2.2.0"


def test_bom_and_windows_line_endings():
    assert pins("﻿flask==2.2.0\r\njinja2==3.1.2\r\n") == [("flask", "2.2.0", 1), ("jinja2", "3.1.2", 2)]


def test_triple_equals():
    text = "foo===1.0\nbar===1.0-custom\n"
    assert pins(text) == [("foo", "1.0", 1)]
    assert notes(text, "skipped") == [(2, "version is not a valid Python version")]


def test_never_crashes_on_odd_input():
    text = "\\\n==\n[extras]\n;\n@\nflask==\n"
    parsed = parse_requirements(text)
    assert parsed.pins == []
```

- [ ] **Step 4: Run the tests to see them fail**

Run: `uv run pytest tests/scanner/test_requirements.py -q`
Expected: FAIL / collection error: `ModuleNotFoundError: No module named 'cve_copilot.scanner.requirements'`

- [ ] **Step 5: Write the parser**

`src/cve_copilot/scanner/requirements.py`:
```python
"""Read a requirements.txt into pinned packages, unpinned lines and skipped lines."""
import re
from collections.abc import Iterator

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import LineNote, ParsedRequirements, Pin

_COMMENT = re.compile(r"(^|\s)#.*$")       # "#" at the start or after a space (not inside URLs)
_HASH = re.compile(r"\s--hash[=\s]\S+")    # pip-compile: --hash=sha256:...
_VCS = ("git+", "hg+", "svn+", "bzr+")


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield (first line number, text), joining lines that end with a backslash."""
    parts: list[str] = []
    start = 0
    for no, raw in enumerate(text.lstrip("﻿").splitlines(), start=1):
        if not parts:
            start = no
        if raw.endswith("\\"):
            parts.append(raw[:-1])
            continue
        parts.append(raw)
        yield start, " ".join(parts)
        parts = []
    if parts:
        yield start, " ".join(parts)


def parse_requirements(text: str) -> ParsedRequirements:
    out = ParsedRequirements()
    for no, raw in _logical_lines(text):
        line = _HASH.sub("", _COMMENT.sub("", raw)).strip()
        if line:
            _classify(no, line, out)
    return out


def _classify(no: int, line: str, out: ParsedRequirements) -> None:
    if line.startswith("-"):
        option = line.split()[0].split("=")[0]
        out.skipped.append(LineNote(no, line, f"pip option {option}"))
        return
    try:
        req = Requirement(line)
    except InvalidRequirement:
        looks_like_path = line.startswith(_VCS) or line.startswith(".") or "/" in line
        out.skipped.append(LineNote(no, line, "URL, VCS or local path" if looks_like_path
                                    else "could not parse"))
        return
    if req.url:
        out.skipped.append(LineNote(no, line, "URL, VCS or local path"))
        return
    specs = list(req.specifier)
    if len(specs) != 1 or specs[0].operator not in ("==", "===") or "*" in specs[0].version:
        out.not_pinned.append(LineNote(no, line, "not pinned"))
        return
    try:
        Version(specs[0].version)
    except InvalidVersion:
        out.skipped.append(LineNote(no, line, "version is not a valid Python version"))
        return
    out.pins.append(Pin(canonicalize_name(req.name), specs[0].version, no, line))
```

- [ ] **Step 6: Run the tests to see them pass**

Run: `uv run pytest tests/scanner/test_requirements.py -q`
Expected: 10 passed. If `test_never_crashes_on_odd_input` raises, the fix is in `_classify` (every branch must end in a note or a pin), not in the test.

- [ ] **Step 7: Commit**

```bash
git add src/cve_copilot/scanner tests/scanner
git commit -m "feat: parse requirements.txt into pins, unpinned and skipped lines

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Version matching (pure functions)

**Files:**
- Create: `src/cve_copilot/scanner/matching.py`, `tests/scanner/test_matching.py`

**Interfaces:**
- Consumes: `AffectedRange(package, introduced, fixed, last_affected)` from `cve_copilot.ingest.models`.
- Produces:
  - `parse_version(text: str) -> Version | None` (cached; `None` if not PEP 440).
  - `in_range(v: Version, r: AffectedRange) -> bool`.
  - `is_affected(v: Version, ranges: Iterable[AffectedRange], versions: Iterable[str]) -> bool`.
  - `lowest_above(v: Version, candidates: Iterable[str]) -> str | None` (lowest valid version strictly above `v`).

- [ ] **Step 1: Write the failing tests**

`tests/scanner/test_matching.py`:
```python
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
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `uv run pytest tests/scanner/test_matching.py -q`
Expected: collection error `No module named 'cve_copilot.scanner.matching'`

- [ ] **Step 3: Write the implementation**

`src/cve_copilot/scanner/matching.py`:
```python
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
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `uv run pytest tests/scanner/test_matching.py -q`
Expected: 10 passed

- [ ] **Step 5: Commit**

```bash
git add src/cve_copilot/scanner/matching.py tests/scanner/test_matching.py
git commit -m "feat: match versions against OSV ranges and explicit version lists

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Read one package from the database (read-only)

**Files:**
- Create: `src/cve_copilot/scanner/db.py`, `tests/scanner/fixture_db.py`, `tests/scanner/test_db.py`

**Interfaces:**
- Consumes: the SQLite schema from `cve_copilot.ingest.store` (`advisories`, `aliases`, `affected`, `affected_versions`, `kev`); `write_db(path, advisories, kev)` and `Advisory`, `AffectedRange`, `KevEntry` for the test fixture.
- Produces:
  - `open_db(path: Path) -> sqlite3.Connection` (read-only; `FileNotFoundError` with "Build it first" if missing).
  - `load_records(con, package: str) -> list[Record]` (sorted by ID; empty list for unknown packages).
  - `kev_ids(con, ids: Iterable[str]) -> set[str]` (which of these IDs are in the KEV table).
  - `tests.scanner.fixture_db.build_fixture_db(path: Path) -> Path` (used again in Tasks 4, 5 and 6).

- [ ] **Step 1: Write the shared fixture database**

This small DB has known answers. Every later scanner test uses it, so the expected results below are worked out by hand.

`tests/scanner/fixture_db.py`:
```python
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
]
KEV = [KevEntry("CVE-2024-9", "2024-05-01", "Unknown")]


def build_fixture_db(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_db(path, ADVISORIES, KEV)
    return path
```

- [ ] **Step 2: Write the failing tests**

`tests/scanner/test_db.py`:
```python
import sqlite3

import pytest

from cve_copilot.ingest.models import AffectedRange
from cve_copilot.scanner.db import kev_ids, load_records, open_db
from tests.scanner.fixture_db import build_fixture_db


@pytest.fixture
def con(tmp_path):
    c = open_db(build_fixture_db(tmp_path / "cve.db"))
    yield c
    c.close()


def test_load_records_for_a_package(con):
    records = load_records(con, "flask")
    assert [r.id for r in records] == ["GHSA-flask-1", "GHSA-flask-2", "PYSEC-2023-1"]
    first = records[0]
    assert first.aliases == ("CVE-2023-1", "PYSEC-2023-1")
    assert first.cvss_score == 7.5
    assert first.summary == "summary of GHSA-flask-1"
    assert first.ranges == (AffectedRange("flask", "0", "2.2.5", None),
                            AffectedRange("flask", "2.3.0", "2.3.2", None))


def test_versions_only_record(con):
    [rec] = load_records(con, "gitlib")
    assert rec.ranges == () and sorted(rec.versions) == ["0.9", "1.0"]


def test_unknown_package_gives_nothing(con):
    assert load_records(con, "not-a-package") == []


def test_kev_ids(con):
    assert kev_ids(con, ["CVE-2024-9", "CVE-2024-10", "GHSA-dj-1"]) == {"CVE-2024-9"}
    assert kev_ids(con, []) == set()


def test_database_is_opened_read_only(con):
    with pytest.raises(sqlite3.OperationalError):
        con.execute("DELETE FROM kev")


def test_missing_db_has_clear_message(tmp_path):
    with pytest.raises(FileNotFoundError, match="Build it first"):
        open_db(tmp_path / "nope" / "cve.db")
```

- [ ] **Step 3: Run the tests to see them fail**

Run: `uv run pytest tests/scanner/test_db.py -q`
Expected: collection error `No module named 'cve_copilot.scanner.db'`

- [ ] **Step 4: Write the implementation**

`src/cve_copilot/scanner/db.py`:
```python
"""Read one package's advisories from the ingest SQLite database (read-only)."""
import sqlite3
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from ..ingest.models import AffectedRange
from .models import Record


def open_db(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise FileNotFoundError(
            f"No vulnerability database at {path}. "
            "Build it first: uv run python -m cve_copilot.ingest --target live (or frozen)")
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)


def load_records(con: sqlite3.Connection, package: str) -> list[Record]:
    ranges: dict[str, list[AffectedRange]] = defaultdict(list)
    for adv_id, intro, fixed, last in con.execute(
            "SELECT advisory_id, introduced, fixed, last_affected FROM affected WHERE package = ?",
            (package,)):
        ranges[adv_id].append(AffectedRange(package, intro, fixed, last))
    versions: dict[str, list[str]] = defaultdict(list)
    for adv_id, version in con.execute(
            "SELECT advisory_id, version FROM affected_versions WHERE package = ?", (package,)):
        versions[adv_id].append(version)

    ids = sorted(ranges.keys() | versions.keys())
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    aliases: dict[str, list[str]] = defaultdict(list)
    for adv_id, alias in con.execute(
            f"SELECT advisory_id, alias FROM aliases WHERE advisory_id IN ({marks})", ids):
        aliases[adv_id].append(alias)
    rows = con.execute(
        f"SELECT id, summary, cvss_score FROM advisories WHERE id IN ({marks}) ORDER BY id", ids)
    return [Record(adv_id, tuple(sorted(aliases[adv_id])), (summary or "").strip(), score,
                   tuple(ranges[adv_id]), tuple(versions[adv_id]))
            for adv_id, summary, score in rows]


def kev_ids(con: sqlite3.Connection, ids: Iterable[str]) -> set[str]:
    wanted = sorted(set(ids))
    if not wanted:
        return set()
    marks = ",".join("?" * len(wanted))
    return {row[0] for row in con.execute(f"SELECT cve_id FROM kev WHERE cve_id IN ({marks})", wanted)}
```

Note on `ranges` order: `test_load_records_for_a_package` expects insertion order from `write_db`, which inserts ranges in list order. If SQLite ever returns them differently, sort with `key=lambda r: (r.introduced or "", r.fixed or "")` in both the code and the test.

- [ ] **Step 5: Run the tests to see them pass**

Run: `uv run pytest tests/scanner/test_db.py -q`
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add src/cve_copilot/scanner/db.py tests/scanner/fixture_db.py tests/scanner/test_db.py
git commit -m "feat: read one package's advisories from SQLite, read-only

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Scan: group duplicates, build findings, sort, pick upgrades

**Files:**
- Create: `src/cve_copilot/scanner/scan.py`, `tests/scanner/test_scan.py`
- Modify: `src/cve_copilot/scanner/__init__.py`

**Interfaces:**
- Consumes: `parse_requirements` (Task 1), `parse_version`, `is_affected`, `lowest_above` (Task 2), `open_db`, `load_records`, `kev_ids` (Task 3), `build_fixture_db` (Task 3).
- Produces:
  - `group_records(records: list[Record]) -> list[list[Record]]`: records linked by any shared ID/alias.
  - `safe_upgrade(version: str, records: list[Record]) -> str | None`.
  - `scan(text: str, db_path: Path) -> ScanReport`: findings sorted malware → KEV → CVSS high→low → package → ID.
  - `cve_copilot.scanner` re-exports `scan` and `parse_requirements`.

- [ ] **Step 1: Write the failing tests**

Hand-worked answers against `fixture_db.py`:
- `flask==2.2.0`: GHSA-flask-1/PYSEC-2023-1 (range 0–2.2.5) and GHSA-flask-2 (0–3.1.3). Per-finding upgrades: 2.2.5 and 3.1.3. Safe upgrade: 2.2.5 is still hit by flask-2, 2.3.2 too, so **3.1.3**.
- `django==4.0`: dj-1 (KEV, 5.0) sorts before dj-2 (9.8, not KEV).

`tests/scanner/test_scan.py`:
```python
import pytest

from cve_copilot.scanner import scan
from cve_copilot.scanner.models import Record
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
    assert scan("flask==2.2.0\n", db).upgrades == {"flask": "3.1.3"}


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
    assert report.upgrades == {"reqeusts": None}


def test_last_affected_and_versions_only(db):
    assert ids(scan("oldlib==1.4\n", db)) == ["GHSA-old-1"]
    assert ids(scan("oldlib==1.4.1\n", db)) == []
    assert ids(scan("gitlib==1.0.0\n", db)) == ["GHSA-git-1"]
    assert scan("oldlib==1.4\n", db).findings[0].upgrade_to is None


def test_bad_version_in_db_does_not_crash(db):
    assert ids(scan("badlib==2.6.5\n", db)) == []             # broken range ignored
    assert ids(scan("badlib==0.5\n", db)) == ["GHSA-bad-1"]   # the valid range still works


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


def test_safe_upgrade_none_when_no_fix():
    from cve_copilot.ingest.models import AffectedRange
    rec = Record("MAL-1", (), "", None, (AffectedRange("x", "0", None, None),), ())
    assert safe_upgrade("1.0", [rec]) is None
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `uv run pytest tests/scanner/test_scan.py -q`
Expected: collection error `cannot import name 'scan' from 'cve_copilot.scanner'`

- [ ] **Step 3: Write the implementation**

`src/cve_copilot/scanner/scan.py`:
```python
"""Match pinned requirements against the advisory database (spec 5.2). No AI here."""
from collections import defaultdict
from contextlib import closing
from pathlib import Path

from .db import kev_ids, load_records, open_db
from .matching import is_affected, lowest_above, parse_version
from .models import Finding, Pin, Record, ScanReport
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
    return {rng.fixed for r in records for rng in r.ranges if rng.fixed}


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
        fixed_versions=tuple(sorted((f for f in fixed if parse_version(f)), key=parse_version)),
        upgrade_to=lowest_above(v, fixed),
    )


def safe_upgrade(version: str, records: list[Record]) -> str | None:
    """Lowest known fixed version above `version` that no known advisory affects."""
    v = parse_version(version)
    candidates = [(pv, f) for f in _fixes(records) if (pv := parse_version(f)) is not None and pv > v]
    for pv, f in sorted(candidates):
        if not any(is_affected(pv, r.ranges, r.versions) for r in records):
            return f
    return None


def _sort_key(f: Finding):
    return (not f.is_malware, not f.in_kev, -(f.cvss_score or 0.0), f.package, f.advisory_id)


def scan(text: str, db_path: Path) -> ScanReport:
    parsed = parse_requirements(text)
    findings: list[Finding] = []
    upgrades: dict[str, str | None] = {}
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
```

`src/cve_copilot/scanner/__init__.py`:
```python
"""Scanner: requirements.txt in, vulnerability findings out. Plain code, no AI."""
from .requirements import parse_requirements
from .scan import scan

__all__ = ["parse_requirements", "scan"]
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `uv run pytest tests/scanner -q`
Expected: all scanner tests pass (10 + 10 + 6 + 12 = 38)

- [ ] **Step 5: Run the whole suite**

Run: `uv run pytest -q`
Expected: 58 (Phase 1) + 38 = 96 passed

- [ ] **Step 6: Commit**

```bash
git add src/cve_copilot/scanner tests/scanner/test_scan.py
git commit -m "feat: scan requirements into sorted, de-duplicated findings with upgrades

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: `Settings.db_dir` and the scanner CLI, first real scan

**Files:**
- Modify: `src/cve_copilot/config.py`, `src/cve_copilot/ingest/__main__.py:38,46`, `tests/test_config.py`
- Create: `src/cve_copilot/scanner/__main__.py`, `tests/scanner/test_cli.py`

**Interfaces:**
- Consumes: `scan` (Task 4), `build_fixture_db` (Task 3), `Settings.from_env()`.
- Produces:
  - `Settings.db_dir(target: str) -> Path`: `data_dir/"live"` or `data_dir/"frozen"/"db"`; `ValueError` otherwise.
  - `cve_copilot.scanner.__main__.main(argv) -> int`: exit 0 = no findings, 1 = findings, 2 = no database / file.
  - `format_report(report: ScanReport) -> str`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_config.py`:
```python


def test_db_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    s = Settings.from_env()
    assert s.db_dir("live") == tmp_path / "live"
    assert s.db_dir("frozen") == tmp_path / "frozen" / "db"
    with pytest.raises(ValueError):
        s.db_dir("other")
```
(Add `import pytest` at the top of `tests/test_config.py` if it isn't there.)

`tests/scanner/test_cli.py`:
```python
from cve_copilot.scanner.__main__ import main
from tests.scanner.fixture_db import build_fixture_db


def setup(tmp_path, monkeypatch, text):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path / "data"))
    req = tmp_path / "requirements.txt"
    req.write_text(text)
    return req


def test_cli_prints_findings_and_exits_1(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "flask==2.2.0\nflask\n-r base.txt\n")
    build_fixture_db(tmp_path / "data" / "live" / "cve.db")
    assert main([str(req)]) == 1
    out = capsys.readouterr().out
    assert "GHSA-flask-1" in out and "GHSA-flask-2" in out
    assert "flask 2.2.0 -> 3.1.3" in out
    assert "line 2" in out and "not pinned" in out
    assert "line 3" in out and "pip option -r" in out


def test_cli_clean_file_exits_0(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "flask==3.1.3\n")
    build_fixture_db(tmp_path / "data" / "frozen" / "db" / "cve.db")
    assert main([str(req), "--target", "frozen"]) == 0
    assert "No known vulnerabilities" in capsys.readouterr().out


def test_cli_missing_db(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "flask==2.2.0\n")
    assert main([str(req)]) == 2
    assert "Build it first" in capsys.readouterr().err
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `uv run pytest tests/test_config.py tests/scanner/test_cli.py -q`
Expected: FAIL: `AttributeError: 'Settings' object has no attribute 'db_dir'` and `No module named 'cve_copilot.scanner.__main__'`

- [ ] **Step 3: Add `db_dir` to `Settings`**

In `src/cve_copilot/config.py`, add this method inside `class Settings`, after `from_env`:
```python

    def db_dir(self, target: str) -> Path:
        """Folder holding cve.db, chroma/ and manifest.json for a build target."""
        if target == "live":
            return self.data_dir / "live"
        if target == "frozen":
            return self.data_dir / "frozen" / "db"
        raise ValueError(f"Unknown target {target!r} (use live or frozen)")
```

In `src/cve_copilot/ingest/__main__.py`, keep one `Settings` object and use the new method. Replace `data_dir = Settings.from_env().data_dir` with:
```python
    settings = Settings.from_env()
    data_dir = settings.data_dir
```
Then replace `data_dir / "live", embed_fn=embed_fn` with `settings.db_dir("live"), embed_fn=embed_fn`, and `data_dir / "frozen" / "db", embed_fn=embed_fn` with `settings.db_dir("frozen"), embed_fn=embed_fn`. (`data_dir` is still used for `raw = data_dir / "frozen" / "raw"`.)

- [ ] **Step 4: Write the CLI**

`src/cve_copilot/scanner/__main__.py`:
```python
"""CLI: uv run python -m cve_copilot.scanner requirements.txt [--target live|frozen]"""
import argparse
import sys
from pathlib import Path

from ..config import Settings
from .models import ScanReport
from .scan import scan


def format_report(report: ScanReport) -> str:
    lines = [f"Checked {len(report.checked)} pinned packages: "
             f"{len(report.findings)} findings in {len(report.upgrades)} packages."]
    if report.findings:
        lines += ["", f"{'PACKAGE':<22} {'VERSION':<12} {'ADVISORY':<22} {'CVSS':>4}  {'FLAG':<7}  FIX"]
        for f in report.findings:
            score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
            flag = "MALWARE" if f.is_malware else ("KEV" if f.in_kev else "")
            lines.append(f"{f.package:<22} {f.version:<12} {f.advisory_id:<22} {score:>4}  "
                         f"{flag:<7}  {f.upgrade_to or 'no fix known'}")
        lines += ["", "Suggested upgrades:"]
        versions = {p.name: p.version for p in report.checked}
        for pkg, target in report.upgrades.items():
            lines.append(f"  {pkg} {versions[pkg]} -> {target}" if target
                         else f"  {pkg} {versions[pkg]}: no fixed version known")
    else:
        lines.append("No known vulnerabilities in the pinned packages.")
    for title, notes in (("Not checked", report.not_pinned), ("Skipped", report.skipped)):
        if notes:
            lines += ["", f"{title}:"]
            lines += [f"  line {n.line_no}: {n.line}  ({n.reason})" for n in notes]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cve_copilot.scanner")
    parser.add_argument("requirements", type=Path)
    parser.add_argument("--target", choices=["live", "frozen"], default="live")
    args = parser.parse_args(argv)
    db_path = Settings.from_env().db_dir(args.target) / "cve.db"
    try:
        text = args.requirements.read_text(encoding="utf-8-sig", errors="replace")
        report = scan(text, db_path)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 2
    print(format_report(report))
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `uv run pytest -q`
Expected: 96 + 1 + 3 = 100 passed (the ingest CLI tests still pass after the `db_dir` change)

- [ ] **Step 6: First real scan against the live database**

```bash
printf 'flask==2.2.0\nDjango==3.2.0\nrequests==2.19.0\npillow==10.0.0\nreqeusts==1.0\nurllib3\n-r base.txt\n' > /tmp/phase2-demo.txt
uv run python -m cve_copilot.scanner /tmp/phase2-demo.txt
```
Expected: exit code 1 and a table. Check these by hand:
- `flask 2.2.0` shows `GHSA-m2qf-hxjv-5gpq` (CVE-2023-30861) **once**, with fix `2.2.5`. `PYSEC-2023-62` must not be a separate row.
- `pillow 10.0.0` shows a finding flagged `KEV` (CVE-2023-4863, libwebp), sorted near the top.
- `reqeusts` shows `MALWARE` in the first row (if the live DB has a `MAL-` record for it; if not, note that and move on).
- `urllib3` is under "Not checked" and `-r base.txt` under "Skipped".

Cross-check flask against OSV directly:
```bash
curl -s -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"flask","ecosystem":"PyPI"},"version":"2.2.0"}' | python3 -c "import json,sys; print(sorted(v['id'] for v in json.load(sys.stdin)['vulns']))"
```
Expected: every ID printed appears in the scan output, either as a finding's main ID or in its aliases. Paste the table into the Task 7 log entry.

- [ ] **Step 7: Commit**

```bash
git add src/cve_copilot/config.py src/cve_copilot/ingest/__main__.py src/cve_copilot/scanner/__main__.py tests/test_config.py tests/scanner/test_cli.py
git commit -m "feat: scanner CLI and shared Settings.db_dir

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: The `scan_cases` exam

**Files:**
- Create: `evals/__init__.py` (empty), `evals/make_scan_cases.py`, `evals/data/scan_cases.jsonl` (generated), `evals/scan_exam.py`, `tests/evals/__init__.py` (empty), `tests/evals/test_scan_exam.py`
- Modify: `pyproject.toml` (`[tool.pytest.ini_options]`)

**Interfaces:**
- Consumes: `scan`, `parse_requirements` (Tasks 1, 4), `Settings.db_dir` (Task 5), `build_fixture_db` (Task 3).
- Produces (Phase 6's `evals/run.py` will call this):
  - `evals.scan_exam.run(cases_path: Path, db_path: Path) -> dict` with keys `metric` (`"scanner_accuracy"`), `cases`, `passed`, `accuracy` (0.0–1.0), `failures` (list of `{id, expected, got}`).
  - Case format (one JSON object per line): `{"id": str, "requirements": str, "expected": {"records": {package: [advisory IDs]}, "not_pinned": [line numbers], "skipped": [line numbers]}, "source": str}`.

- [ ] **Step 1: Let pytest import `evals`**

In `pyproject.toml`, change the pytest section to:
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
```

- [ ] **Step 2: Write the failing scorer test**

`tests/evals/test_scan_exam.py`:
```python
import json

from evals.scan_exam import run
from tests.scanner.fixture_db import build_fixture_db


def write_cases(path, cases):
    path.write_text("".join(json.dumps(c) + "\n" for c in cases))
    return path


def test_run_scores_exact_matches(tmp_path):
    db = build_fixture_db(tmp_path / "cve.db")
    cases = write_cases(tmp_path / "cases.jsonl", [
        {"id": "right", "requirements": "flask==2.2.0\nurllib3\n-r x.txt\n",
         "expected": {"records": {"flask": ["PYSEC-2023-1", "GHSA-flask-1", "GHSA-flask-2"]},
                      "not_pinned": [2], "skipped": [3]}},
        {"id": "wrong", "requirements": "flask==3.1.3\n",
         "expected": {"records": {"flask": ["GHSA-flask-2"]}, "not_pinned": [], "skipped": []}},
    ])
    result = run(cases, db)
    assert result["metric"] == "scanner_accuracy"
    assert (result["cases"], result["passed"], result["accuracy"]) == (2, 1, 0.5)
    [failure] = result["failures"]
    assert failure["id"] == "wrong"
    assert failure["got"]["records"] == {}
```

- [ ] **Step 3: Run it to see it fail**

Run: `uv run pytest tests/evals -q`
Expected: collection error `No module named 'evals.scan_exam'`

- [ ] **Step 4: Write the scorer**

`evals/scan_exam.py`:
```python
"""Scan exam: run the scanner on every case and compare with the answer key (exact match).

    uv run python -m evals.scan_exam [--target frozen|live]
"""
import argparse
import json
import sys
from pathlib import Path

from cve_copilot.config import Settings
from cve_copilot.scanner import scan
from cve_copilot.scanner.models import ScanReport

CASES = Path(__file__).parent / "data" / "scan_cases.jsonl"


def _answer(report: ScanReport) -> dict:
    records: dict[str, set[str]] = {}
    for f in report.findings:
        records.setdefault(f.package, set()).update(f.records)
    return {"records": {p: sorted(ids) for p, ids in sorted(records.items())},
            "not_pinned": [n.line_no for n in report.not_pinned],
            "skipped": [n.line_no for n in report.skipped]}


def _normalise(expected: dict) -> dict:
    return {"records": {p: sorted(ids) for p, ids in sorted(expected["records"].items()) if ids},
            "not_pinned": expected["not_pinned"], "skipped": expected["skipped"]}


def run(cases_path: Path, db_path: Path) -> dict:
    cases = [json.loads(line) for line in cases_path.read_text().splitlines() if line.strip()]
    failures = []
    for case in cases:
        got, want = _answer(scan(case["requirements"], db_path)), _normalise(case["expected"])
        if got != want:
            failures.append({"id": case["id"], "expected": want, "got": got})
    passed = len(cases) - len(failures)
    return {"metric": "scanner_accuracy", "cases": len(cases), "passed": passed,
            "accuracy": passed / len(cases) if cases else 0.0, "failures": failures}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.scan_exam")
    parser.add_argument("--target", choices=["live", "frozen"], default="frozen")
    args = parser.parse_args(argv)
    result = run(CASES, Settings.from_env().db_dir(args.target) / "cve.db")
    print(json.dumps(result, indent=2))
    return 0 if result["accuracy"] == 1.0 else 1


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the test to see it pass**

Run: `uv run pytest tests/evals -q`
Expected: 1 passed

- [ ] **Step 6: Write the case generator**

Every package used here is in `data/frozen/packages.txt`, so the frozen snapshot holds all of its advisories. Line-number expectations are written by hand; the generator refuses to write the file if the parser disagrees with them.

`evals/make_scan_cases.py`:
```python
"""Write evals/data/scan_cases.jsonl. Run once by hand, review the diff, commit.

The expected findings come from the OSV.dev API, which does its own version
matching, so the exam checks our scanner against an independent answer key (D19).
Only IDs present and not withdrawn in the frozen snapshot are kept, so the key
matches the frozen data even if OSV adds advisories later.

    uv run python -m evals.make_scan_cases
"""
import json
import sys
from datetime import date
from pathlib import Path

import httpx

from cve_copilot.config import PROJECT_ROOT
from cve_copilot.scanner import parse_requirements

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
SNAPSHOT = PROJECT_ROOT / "data" / "frozen" / "raw" / "osv"
OUT = Path(__file__).parent / "data" / "scan_cases.jsonl"

MIXED = ("# app requirements\n"                                      # 1
         "-r base.txt\n"                                             # 2 skipped
         "Flask==2.2.0  # web framework\n"                           # 3
         "requests[socks]==2.19.0 ; python_version >= '3.8'\n"       # 4
         "django>=4.2\n"                                             # 5 not pinned
         "-e git+https://github.com/pallets/click.git#egg=click\n"   # 6 skipped
         "urllib3\n"                                                 # 7 not pinned
         "\n"                                                        # 8
         "PyYAML==5.3 \\\n"                                          # 9
         "    --hash=sha256:aaaa \\\n"                               # 10
         "    --hash=sha256:bbbb\n"                                  # 11
         "    # via -r requirements.in\n"                            # 12
         "git+https://github.com/psf/black.git\n")                   # 13 skipped

# (case id, requirements text, expected "not pinned" line numbers, expected "skipped" line numbers)
CASES = [
    ("flask-2.2.0", "flask==2.2.0\n", [], []),
    ("flask-2.3.1", "flask==2.3.1\n", [], []),
    ("flask-3.1.2", "flask==3.1.2\n", [], []),
    ("django-3.2.0", "django==3.2.0\n", [], []),
    ("django-4.2.16", "Django==4.2.16\n", [], []),
    ("django-prerelease", "django==4.2rc1\n", [], []),
    ("werkzeug-2.2.2", "werkzeug==2.2.2\n", [], []),
    ("jinja2-2.10", "Jinja2==2.10\n", [], []),
    ("requests-2.19.0", "requests==2.19.0\n", [], []),
    ("urllib3-1.26.4", "urllib3==1.26.4\n", [], []),
    ("pyyaml-5.3", "PyYAML==5.3\n", [], []),
    ("pillow-10.0.0-kev", "Pillow==10.0.0\n", [], []),
    ("cryptography-3.3.2", "cryptography==3.3.2\n", [], []),
    ("aiohttp-3.8.1", "aiohttp==3.8.1\n", [], []),
    ("sqlalchemy-1.2.0", "SQLAlchemy==1.2.0\n", [], []),
    ("paramiko-2.4.0", "paramiko==2.4.0\n", [], []),
    ("lxml-4.6.2", "lxml==4.6.2\n", [], []),
    ("setuptools-65.5.0", "setuptools==65.5.0\n", [], []),
    ("gunicorn-20.0.4", "gunicorn==20.0.4\n", [], []),
    ("starlette-0.27.0", "starlette==0.27.0\n", [], []),
    ("litellm-1.40.0", "litellm==1.40.0\n", [], []),
    ("langflow-1.0.0", "langflow==1.0.0\n", [], []),
    ("unknown-package", "definitely-not-a-real-package-cvecopilot==1.0\n", [], []),
    ("windows-bom-crlf", "﻿jinja2==2.10\r\nwerkzeug==2.2.2\r\n", [], []),
    ("mixed-file", MIXED, [5, 7], [2, 6, 13]),
]


def _snapshot_ids() -> set[str]:
    return {p.stem for p in SNAPSHOT.glob("*.json")
            if not json.loads(p.read_bytes()).get("withdrawn")}


def _query_osv(pins) -> list[list[str]]:
    body = {"queries": [{"package": {"name": p.name, "ecosystem": "PyPI"}, "version": p.version}
                        for p in pins]}
    resp = httpx.post(OSV_QUERYBATCH, json=body, timeout=60)
    resp.raise_for_status()
    results = resp.json()["results"]
    if any("next_page_token" in r for r in results):
        sys.exit("OSV returned a paged result; this generator does not handle paging")
    return [sorted(v["id"] for v in r.get("vulns", [])) for r in results]


def main() -> int:
    known = _snapshot_ids()
    rows = []
    for case_id, text, not_pinned, skipped in CASES:
        parsed = parse_requirements(text)
        got_np = [n.line_no for n in parsed.not_pinned]
        got_sk = [n.line_no for n in parsed.skipped]
        if (got_np, got_sk) != (not_pinned, skipped):
            sys.exit(f"{case_id}: parser gives not_pinned={got_np} skipped={got_sk}, "
                     f"hand-written answer is {not_pinned} / {skipped}")
        records, not_in_snapshot = {}, []
        if parsed.pins:
            for pin, osv_ids in zip(parsed.pins, _query_osv(parsed.pins)):
                in_snap = [i for i in osv_ids if i in known]
                not_in_snapshot += [i for i in osv_ids if i not in known]
                if in_snap:
                    records.setdefault(pin.name, []).extend(in_snap)
        rows.append({"id": case_id, "requirements": text,
                     "expected": {"records": records, "not_pinned": not_pinned, "skipped": skipped},
                     "source": f"api.osv.dev {date.today().isoformat()}",
                     "not_in_snapshot": not_in_snapshot})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"Wrote {len(rows)} cases to {OUT}; "
          f"{sum(len(r['not_in_snapshot']) for r in rows)} OSV IDs not in the snapshot were left out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 7: Generate the cases and look at them**

```bash
uv run python -m evals.make_scan_cases
python3 -c "import json; [print(c['id'], {k: len(v) for k, v in c['expected']['records'].items()}, c['not_in_snapshot']) for c in map(json.loads, open('evals/data/scan_cases.jsonl'))]"
```
Expected: `Wrote 25 cases`. Check that:
- `flask-2.2.0` includes `GHSA-m2qf-hxjv-5gpq` and `PYSEC-2023-62`.
- `pillow-10.0.0-kev` is not empty.
- `unknown-package` has no records.
- `not_in_snapshot` is empty or nearly empty. Anything there appeared on OSV after the snapshot; note the count in the log.

- [ ] **Step 8: Build the frozen DB and sit the exam**

```bash
uv run python -m cve_copilot.ingest --target frozen     # about 1.5 minutes
uv run python -m evals.scan_exam --target frozen
```
Expected: `"accuracy": 1.0`, exit 0.

**If a case fails**, work through it with superpowers:systematic-debugging before changing anything. For each failing case, compare `expected` and `got` and decide which one is wrong:
- **Scanner bug** (e.g. a range read wrongly): add a failing unit test in `tests/scanner/`, fix, and re-run the exam.
- **Answer-key difference** (OSV matched through data we deliberately skip, e.g. a `GIT` range or an invalid version string, D12): leave the scanner alone and don't edit the expected answer by hand. Record the case, the IDs and the reason in the log's Challenges table, and discuss it with your human partner before changing the case list.

Never "fix" the exam by copying the scanner's output into the answer key.

- [ ] **Step 9: Run the whole suite and commit**

Run: `uv run pytest -q`
Expected: 101 passed

```bash
git add pyproject.toml evals tests/evals
git commit -m "feat: scan_cases exam with an OSV.dev answer key

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Log the day, update the spec, merge

**Files:**
- Modify: `docs/PROJECT_LOG.md`, `docs/superpowers/specs/2026-09-26-cve-copilot-design.md`

- [ ] **Step 1: Update the spec**

In section 5.2, under **Output**, add:
```markdown
- Advisories that share an ID or alias (the same bug stored as GHSA and PYSEC) become **one** finding; `records` lists which stored advisories matched (D15).
- Sort order: malware (`MAL-`) first, then in-KEV, then CVSS high to low (D16).
- Environment markers are not evaluated; marked lines are always checked (D17).
- Besides the per-finding upgrade, each vulnerable package gets one **safe upgrade**: the lowest known fixed version that no known advisory affects (D18).
```
In section 11, change Phase 2's row to `✅ Done <date>: …`.

- [ ] **Step 2: Update the project log**

In `docs/PROJECT_LOG.md`:
- Add D15–D19 from this plan to the decision log (short versions).
- Add a daily journal entry: what was built, the demo table from Task 5 Step 6, the exam result (`N/N cases, accuracy X%`, real numbers only), what was learned, open questions, next (Phase 3: retrieval + router).
- Fill in the results dashboard row "Scanner accuracy (scan cases)" with the real number and the date.
- Add any real problems hit during this phase to "Challenges and fixes".

- [ ] **Step 3: Commit, review, merge**

```bash
git add docs
git commit -m "docs: Phase 2 complete, scanner accuracy logged

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
Then use superpowers:requesting-code-review on the branch, fix what it finds, and use superpowers:finishing-a-development-branch to merge into `main`.
