# Phase 3: Retrieval + Router Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Given a user question, decide which kind of question it is (router), then fetch the advisories that answer it (retriever), and measure that with the `retrieval` exam (recall@5 ≥ 90%).

**Architecture:** A new package `src/cve_copilot/rag/`. `router.py` uses rules first (advisory IDs, then package names found in the database) and asks the LLM only to choose between `concept` and `chat` (D8). `retriever.py` turns a `Route` into a list of `Doc`s: exact SQLite lookups for IDs, meaning-ranked advisories for a package, Chroma search for concepts. Duplicate advisories (GHSA + PYSEC copies of one bug) are merged into one `Doc`, using a small shared helper moved out of the scanner. A CLI (`python -m cve_copilot.rag "question"`) shows the route and documents. The exam (`evals/retrieval_exam.py`) runs router + retriever on hand-written questions.

**Tech Stack:** Python 3.12 (uv), `sqlite3`, `chromadb` (read), fastembed via `cve_copilot.embeddings`, `packaging.utils.canonicalize_name`, pytest.

**Spec:** `docs/superpowers/specs/2026-09-26-cve-copilot-design.md` (sections 5.3, 5.4 router + retriever, 8, 9, 11)

## Global Constraints

- Python 3.12, managed with `uv`. Run everything with `uv run ...`.
- Plain Python modules only; no LangChain or LlamaIndex.
- Unit tests make no network calls and no real LLM calls (`LLM=fake` via `cve_copilot.llm.fake`), and never load the real embedding model (tests pass a fake `embed_fn`).
- Router: **rules first, then the LLM only if the rules don't decide** (spec 5.4, D8).
- ID patterns: `CVE-\d{4}-\d{4,}`, `GHSA-xxxx-xxxx-xxxx`, `PYSEC-\d{4}-\d+` (plus `MAL-\d{4}-\d+`, see D23).
- Package names are canonicalised with `packaging.utils.canonicalize_name`.
- The database is opened read-only (`scanner.db.open_db`); reading must not change files under `data/frozen/` (checked: `git status` stays clean after a Chroma query).
- Retrieval recall@5 pass mark on the `retrieval` exam: **≥ 90%**.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions made while planning (log as D23–D27)

Found by querying `data/frozen/db` and `data/live/cve.db` on 2026-10-01.

- **D23. The router also recognises `MAL-` IDs and lower-case IDs.** Users paste `ghsa-…` from URLs and ask about malware reports. IDs are normalised (`CVE`/`PYSEC`/`MAL` upper case, GHSA body lower case, as stored).
- **D24. Duplicate advisories are merged in retrieval too.** A Chroma search for "debugger lets attacker run code" returns `GHSA-2g68-c3qc-8985` *and* `PYSEC-2026-2043` (the same bug) as the top two hits, wasting one of five slots. The retriever asks Chroma for 4×k hits, merges records that share an ID or alias (GHSA preferred, as in D15), then keeps k. The scanner's grouping code moves to `cve_copilot/ids.py` so both use one implementation.
- **D25. Package names that are common words need a cue.** The live DB has 8,012 package names, and some are English words (`keep`, `late`, `safety`, `black`, `click`, `future`, `pip`, `llm`, …). "Is it safe to keep my sessions?" must not route to the package `keep`. Names on a short ambiguous list count only with a cue: backticks or quotes, a version right after (`black 22.1`, `pip==23.0`), or the word package/library/module next to it.
- **D26. The package route returns the k advisories most related to the question, not all of them.** The spec said "all advisories for that package", but Django has 321 in the frozen data, far too many for the generator's prompt. The package's advisories are ranked by meaning (their stored Chroma vectors against the question vector). Malware records (not in the index, D11) come first because they matter most.
- **D27. The exam's expected answers are hand-picked by reading advisories, and questions are paraphrased.** Each question is written in my own words (not the advisory's summary text), so the exam tests search by meaning, not word copying. The expected ID is the advisory I read; a test checks every expected ID exists in the frozen DB. Retrieval counts a hit when the expected ID is the doc's ID or one of its aliases.

## Review Focus

1. **A package name glued to punctuation or a version** (`flask?`, `Flask's`, `flask==2.2.0`, `mcp-atlassian.`) must still be found. Tested in Task 2 (`test_package_names_with_punctuation_and_versions`).
2. **A question with an ID that is not in the database** (`CVE-1999-0001`) must take the id route and return no documents, not fall through to a meaning search that returns something unrelated. Tested in Task 3 (`test_unknown_id_returns_nothing`).
3. **The LLM fallback replying with junk** (not JSON, or an unknown route) must give the `concept` route marked `by="default"`, not crash. Tested in Task 2 (`test_llm_junk_defaults_to_concept`).
4. **Asking about a CVE that is stored twice** (GHSA + PYSEC) must give one document with both IDs. Tested in Task 3 (`test_cve_alias_lookup_merges_duplicates`).
5. **No database built yet** must give the "Build it first" message (exit 2 in the CLI), not a traceback. Tested in Task 4 (`test_cli_missing_db`).

---

## File map

| File | Responsibility |
|---|---|
| `src/cve_copilot/ids.py` | `group_ids(pairs)` and `main_id(ids)`, shared by scanner and retriever |
| `src/cve_copilot/scanner/scan.py` | Use `ids.group_ids` / `ids.main_id` (behaviour unchanged) |
| `src/cve_copilot/rag/__init__.py` | Re-exports `route_question`, `retrieve`, `Route`, `Doc` |
| `src/cve_copilot/rag/models.py` | `Route`, `Doc` dataclasses |
| `src/cve_copilot/rag/router.py` | `find_ids`, `find_packages`, `route_question` |
| `src/cve_copilot/rag/retriever.py` | `package_names`, `load_docs`, `retrieve` |
| `src/cve_copilot/rag/__main__.py` | CLI: route + documents for one question |
| `evals/data/retrieval.jsonl` | Exam questions |
| `evals/retrieval_exam.py` | Runs the exam, prints recall@5 and route accuracy |
| `tests/test_ids.py`, `tests/rag/*` , `tests/evals/test_retrieval_exam.py` | Tests |

---

### Task 1: Shared ID grouping (`ids.py`), scanner uses it

**Files:** Create `src/cve_copilot/ids.py`, `tests/test_ids.py`; modify `src/cve_copilot/scanner/scan.py`.

**Interfaces:**
- Produces: `group_ids(pairs: Iterable[tuple[str, Iterable[str]]]) -> list[list[str]]` — groups record IDs that share any ID or alias; each group is sorted, groups sorted by their smallest ID. `main_id(ids: Iterable[str]) -> str` — GHSA first, then PYSEC, then others, ties by text.

- [ ] **Step 1: Write the failing tests**

```python
from cve_copilot.ids import group_ids, main_id


def test_records_sharing_an_alias_are_grouped():
    pairs = [("GHSA-a", ["CVE-1", "PYSEC-1"]), ("PYSEC-1", ["CVE-1"]), ("GHSA-b", ["CVE-2"])]
    assert group_ids(pairs) == [["GHSA-a", "PYSEC-1"], ["GHSA-b"]]


def test_shared_alias_links_records_that_do_not_name_each_other():
    assert group_ids([("GHSA-a", ["CVE-1"]), ("PYSEC-9", ["CVE-1"])]) == [["GHSA-a", "PYSEC-9"]]


def test_main_id_prefers_ghsa_then_pysec():
    assert main_id(["PYSEC-1", "GHSA-z", "MAL-1"]) == "GHSA-z"
    assert main_id(["PYSEC-2", "MAL-1", "PYSEC-1"]) == "PYSEC-1"
    assert main_id(["MAL-2", "CVE-1"]) == "CVE-1"
```

- [ ] **Step 2:** `uv run pytest tests/test_ids.py -q` → FAIL (module missing).
- [ ] **Step 3: Implement** — move the union-find and `_ID_RANK` from `scanner/scan.py` into `ids.py`:

```python
"""Advisory IDs: which stored records are the same bug, and which ID to show first."""
from collections import defaultdict
from collections.abc import Iterable

_ID_RANK = {"GHSA": 0, "PYSEC": 1}


def group_ids(pairs: Iterable[tuple[str, Iterable[str]]]) -> list[list[str]]:
    """Record IDs that share any ID or alias describe the same bug (e.g. GHSA + PYSEC)."""
    pairs = [(rid, list(aliases)) for rid, aliases in pairs]
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for rid, aliases in pairs:
        for alias in aliases:
            parent[find(alias)] = find(rid)
    groups: dict[str, list[str]] = defaultdict(list)
    for rid, _ in pairs:
        groups[find(rid)].append(rid)
    return sorted((sorted(g) for g in groups.values()), key=lambda g: g[0])


def main_id(ids: Iterable[str]) -> str:
    return min(ids, key=lambda i: (_ID_RANK.get(i.split("-")[0], 9), i))
```

In `scanner/scan.py`, `group_records` becomes a wrapper (same output order as before) and `_main_id` is replaced by `ids.main_id`:

```python
def group_records(records: list[Record]) -> list[list[Record]]:
    """Records that share any ID or alias describe the same bug (e.g. GHSA + PYSEC)."""
    by_id = {r.id: r for r in records}
    return [[by_id[i] for i in g] for g in group_ids((r.id, r.aliases) for r in records)]
```

- [ ] **Step 4:** `uv run pytest -q` → all pass (123 old + 3 new); `uv run python -m evals.scan_exam` still 26/26.
- [ ] **Step 5: Commit** `refactor: share advisory grouping between scanner and retrieval`.

---

### Task 2: Models and router

**Files:** Create `src/cve_copilot/rag/{__init__,models,router}.py`, `tests/rag/__init__.py`, `tests/rag/test_router.py`.

**Interfaces:**
- Produces:
  - `Route(kind: str, ids: tuple[str,...]=(), packages: tuple[str,...]=(), by: str="rules")`, kind ∈ `id|package|concept|chat`, by ∈ `rules|llm|default`.
  - `Doc(id, aliases, packages, summary, details, cvss_score, in_kev, flagged, flag_reason, affected, score=None)`; `affected` is a tuple of readable strings such as `"flask: from 0, fixed in 2.2.5"`.
  - `find_ids(question) -> tuple[str, ...]` (normalised, order of appearance, no repeats).
  - `find_packages(question, known: Collection[str]) -> tuple[str, ...]`.
  - `route_question(question, known_packages, *, settings=None) -> Route`.

- [ ] **Step 1: Write the failing tests** (`tests/rag/test_router.py`):

```python
import json

import pytest

from cve_copilot.config import Settings
from cve_copilot.llm import fake
from cve_copilot.rag.router import find_ids, find_packages, route_question

KNOWN = {"flask", "django", "mcp-atlassian", "keep", "black", "pip", "requests"}
FAKE = Settings.from_env().__class__(**{**Settings.from_env().__dict__, "llm": "fake"})


def test_finds_and_normalises_ids():
    q = "Is ghsa-2G68-C3QC-8985 the same as cve-2024-34069? Also PYSEC-2026-2043 and MAL-2024-1."
    assert find_ids(q) == ("GHSA-2g68-c3qc-8985", "CVE-2024-34069", "PYSEC-2026-2043", "MAL-2024-1")


def test_ids_are_not_repeated_and_partial_ids_are_ignored():
    assert find_ids("CVE-2024-34069 and CVE-2024-34069, not CVE-24-1") == ("CVE-2024-34069",)


def test_package_names_with_punctuation_and_versions():
    q = "Is Flask's session safe? flask==2.2.0 or MCP_Atlassian. and django?"
    assert find_packages(q, KNOWN) == ("flask", "mcp-atlassian", "django")


def test_common_word_packages_need_a_cue():
    assert find_packages("Is it safe to keep my session cookies?", KNOWN) == ()
    assert find_packages("Is the keep package vulnerable?", KNOWN) == ("keep",)
    assert find_packages("Should I upgrade black 22.1?", KNOWN) == ("black",)
    assert find_packages("is `pip` affected", KNOWN) == ("pip",)
    assert find_packages("pip==23.0 problems", KNOWN) == ("pip",)


def test_id_route_wins_and_keeps_packages():
    r = route_question("Is flask affected by CVE-2023-30861?", KNOWN, settings=FAKE)
    assert (r.kind, r.ids, r.packages, r.by) == ("id", ("CVE-2023-30861",), ("flask",), "rules")


def test_package_route_without_llm():
    fake.set_responses([])
    r = route_question("What are the worst bugs in django?", KNOWN, settings=FAKE)
    assert (r.kind, r.packages, r.by) == ("package", ("django",), "rules")
    assert fake.calls == []


@pytest.mark.parametrize("answer, kind", [("concept", "concept"), ("chat", "chat")])
def test_llm_decides_concept_or_chat(answer, kind):
    fake.set_responses([json.dumps({"route": answer})])
    r = route_question("what is a CVE?", KNOWN, settings=FAKE)
    assert (r.kind, r.by) == (kind, "llm")
    assert fake.calls[0]["json_mode"] is True


@pytest.mark.parametrize("reply", ["not json", '{"route": "weather"}', "[]"])
def test_llm_junk_defaults_to_concept(reply):
    fake.set_responses([reply])
    r = route_question("tell me about request smuggling", KNOWN, settings=FAKE)
    assert (r.kind, r.by) == ("concept", "default")
```

(Use `dataclasses.replace(Settings.from_env(), llm="fake")` for `FAKE` — cleaner than the line above.)

- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement** `models.py` (frozen dataclasses above) and `router.py`:

```python
"""Pick a route for a question: rules first, the LLM only when rules don't decide (D8)."""
import json
import re
from collections.abc import Collection

from packaging.utils import canonicalize_name

from .. import llm
from ..config import Settings
from .models import Route

_ID_RE = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|MAL-\d{4}-\d+)\b",
    re.IGNORECASE)
_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# Package names that are also everyday words (D25): they need a cue to count.
AMBIGUOUS = frozenset("""
    accelerate black click dash distributed fabric feast flaw flower future glance hazard
    horizon intake keep late lightning llm markdown max notebook paste pip plane planet
    priority reflex safety salt sentry signify spam styling supervisor swift trickery
    trove tutor weave wheel""".split())
_ROUTER_PROMPT = (
    "You route questions for an assistant that answers questions about security "
    "vulnerabilities in Python packages. Reply with JSON only: {\"route\": \"concept\"} "
    "if answering needs a search of the vulnerability database (a kind of bug, attack or "
    "security problem), or {\"route\": \"chat\"} if it does not (greetings, thanks, "
    "general definitions such as 'what is a CVE?', questions about the assistant).")


def _normalise_id(raw: str) -> str:
    prefix, rest = raw.split("-", 1)
    prefix = prefix.upper()
    return f"{prefix}-{rest.lower() if prefix == 'GHSA' else rest.upper()}"


def find_ids(question: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_normalise_id(m) for m in _ID_RE.findall(question)))


def _cued(question: str, word: str) -> bool:
    w = re.escape(word)
    return bool(re.search(
        rf"`{w}`|['\"]{w}['\"]|\b{w}\s*(?:==|v?\d)|\b(?:package|library|module)\s+{w}\b"
        rf"|\b{w}\s+(?:package|library|module)\b", question, re.IGNORECASE))


def find_packages(question: str, known: Collection[str]) -> tuple[str, ...]:
    found = []
    for word in _WORD_RE.findall(question):
        word = word.rstrip("._-")
        if word.lower().endswith("'s"):
            word = word[:-2]
        name = canonicalize_name(word)
        if name in known and (name not in AMBIGUOUS or _cued(question, word)):
            found.append(name)
    return tuple(dict.fromkeys(found))


def _ask_llm(question: str, settings: Settings | None) -> Route:
    reply = llm.complete([{"role": "system", "content": _ROUTER_PROMPT},
                          {"role": "user", "content": question}], json_mode=True, settings=settings)
    try:
        kind = json.loads(reply).get("route")
    except (ValueError, AttributeError):
        kind = None
    if kind in ("concept", "chat"):
        return Route(kind, by="llm")
    return Route("concept", by="default")   # searching never hurts; a wrong "chat" would


def route_question(question: str, known_packages: Collection[str], *,
                   settings: Settings | None = None) -> Route:
    ids, packages = find_ids(question), find_packages(question, known_packages)
    if ids:
        return Route("id", ids=ids, packages=packages)
    if packages:
        return Route("package", packages=packages)
    return _ask_llm(question, settings)
```

Note on `'s`: `_WORD_RE` stops at the apostrophe, so `Flask's` yields `Flask` and `s`; the `'s` strip is kept for curly-quote-free safety only if a test shows it is needed — remove it if unused.

- [ ] **Step 4:** run → PASS.
- [ ] **Step 5: Commit** `feat: router picks id, package, concept or chat route`.

---

### Task 3: Retriever

**Files:** Create `src/cve_copilot/rag/retriever.py`, `tests/rag/fixture_index.py`, `tests/rag/test_retriever.py`.

**Interfaces:**
- Consumes: `Route`, `Doc` (Task 2); `group_ids`, `main_id` (Task 1); `scanner.db.open_db`; `ingest.index.COLLECTION`, `build_index`.
- Produces:
  - `package_names(db_path: Path) -> frozenset[str]` (cached per path).
  - `load_docs(con, ids: Iterable[str]) -> list[Doc]` — looks up records by ID **or alias**, merges duplicates, one `Doc` per bug, ordered by first appearance in `ids`.
  - `retrieve(route: Route, question: str, db_dir: Path, *, k: int = 5, embed_fn=embed) -> list[Doc]`.

Test fixture: reuse `tests/scanner/fixture_db.ADVISORIES` (it already has GHSA+PYSEC duplicates, a KEV alias and malware) to write `cve.db`, and `build_index` with a fake embedder over the non-malware ones. The fake embedder maps text to a vector from keyword counts so meaning search is predictable:

```python
VOCAB = ["flask", "django", "session", "sql", "pin"]
def fake_embed(texts):
    return [[float(t.lower().count(w)) + 0.01 for w in VOCAB] for t in texts]
```

- [ ] **Step 1: Write the failing tests** — cover: id lookup by main ID; `test_cve_alias_lookup_merges_duplicates` (`CVE-2023-1` → one Doc `GHSA-flask-1` with `PYSEC-2023-1` in aliases); `test_unknown_id_returns_nothing`; KEV flag via alias (`GHSA-dj-1`); package route returns ≤ k docs, malware first for `reqeusts`, ranked by the fake vectors; concept route merges duplicates and returns ≤ k; chat route returns `[]` without touching the DB; `affected` strings (`"flask: from 0, fixed in 2.2.5"`, `"oldlib: from 1.0, last affected 1.4"`, `"gitlib: versions 0.9, 1.0"`); `package_names` contains `flask` and `reqeusts`; missing DB raises `FileNotFoundError` with "Build it first".
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement** `retriever.py`:
  - `load_docs`: `SELECT advisory_id FROM aliases WHERE alias IN (…)` ∪ IDs themselves that exist; then fetch the whole alias neighbourhood (aliases of those records, and records whose aliases include them) so a group is complete; read advisories, aliases, ranges, versions, KEV; group with `group_ids`; build one `Doc` per group (main ID by `main_id`; summary/details from the main record, else first non-empty; `cvss_score` = max; `in_kev` if any ID/alias is in `kev`; `flagged` if any record is flagged, reasons joined; `affected` deduped in order).
  - Chroma client cached per folder (`functools.lru_cache`) and opened only for package/concept routes.
  - package route: all record IDs for the packages (`affected` ∪ `affected_versions`) → `load_docs` → score each Doc by the best cosine similarity of its records' stored vectors (`col.get(ids=…, include=["embeddings"])`) to `embed_fn([question])[0]`; Docs with no stored vector (malware) get score `None` and sort first; keep k.
  - concept route: `col.query(query_embeddings=…, n_results=4*k, include=["distances"])` → `load_docs` in hit order → score = 1 − distance of its best hit → keep k.
- [ ] **Step 4:** run → PASS; also `uv run pytest -q`.
- [ ] **Step 5: Commit** `feat: retriever returns merged advisory docs per route`.

---

### Task 4: CLI and first real queries

**Files:** Create `src/cve_copilot/rag/__main__.py`, `tests/rag/test_cli.py`.

- `uv run python -m cve_copilot.rag "question" [--target frozen|live] [-k 5]` prints `Route: package (rules) packages=flask`, then one line per Doc: `ID  CVSS  KEV  score  summary[:70]`.
- Missing DB → message on stderr, exit 2 (`test_cli_missing_db`).
- Test with the fixture DB + fake LLM + fake embedder (inject via a `main(argv, embed_fn=...)` parameter).
- Then run three real questions on the frozen data and paste the output into the log (Task 6).
- Commit `feat: rag CLI shows route and retrieved documents`.

---

### Task 5: The `retrieval` exam

**Files:** Create `evals/data/retrieval.jsonl`, `evals/retrieval_exam.py`, `tests/evals/test_retrieval_exam.py`.

Item format: `{"id": "...", "question": "...", "route": "id|package|concept|chat", "expected": ["GHSA-..."]}`. `expected` lists the distinct bugs the top 5 must contain (one per item, except where stated). Chat items have `"expected": []` and count only for route accuracy.

Scoring (`run(cases_path, db_dir, *, k=5, embed_fn=embed, settings=None) -> dict`):
- item recall = (expected IDs found among the top-k docs' IDs ∪ aliases) / len(expected);
- `recall_at_5` = mean item recall over items with non-empty `expected`;
- `route_accuracy` = share of all items whose route kind matches `route`;
- items with an empty `expected` and `route` ≠ chat (an unknown ID) pass when no docs come back;
- `main()` prints JSON and exits 1 if `recall_at_5 < 0.90`.

Unit tests (no LLM, fixture DB): scoring counts an alias hit; a missed item lowers recall; `test_expected_ids_exist_in_frozen_db` loads every `expected` ID from `evals/data/retrieval.jsonl` and checks it exists in `data/frozen/db/cve.db` (by ID).

Questions (D27: paraphrased, written by reading the advisory): 31 items — 5 id, 8 package, 14 concept, 4 chat:

| id | route | question | expected |
|---|---|---|---|
| id-cve-alias | id | What is CVE-2024-34069 about? | GHSA-2g68-c3qc-8985 |
| id-ghsa-lower | id | explain ghsa-m2qf-hxjv-5gpq | GHSA-m2qf-hxjv-5gpq |
| id-pysec | id | Is PYSEC-2018-19 serious? | GHSA-232r-66cg-79px |
| id-kev | id | Tell me about CVE-2025-3248 | GHSA-rvqx-wpfh-mfx7 |
| id-unknown | id | What is CVE-1999-0001? | (none) |
| pkg-werkzeug-debugger | package | Can someone run code through the werkzeug debugger? | GHSA-2g68-c3qc-8985 |
| pkg-requests-netrc | package | Does requests leak my netrc password to other sites? | GHSA-9hjg-9r4m-mvj7 |
| pkg-pyyaml-load | package | Is loading untrusted files with pyyaml dangerous? | GHSA-rprw-h62v-c2w7 |
| pkg-paramiko-terrapin | package | Is paramiko affected by the Terrapin SSH attack? | GHSA-45x7-px36-x8w8 |
| pkg-flask-vary | package | Can flask session cookies end up in a shared cache? | GHSA-m2qf-hxjv-5gpq |
| pkg-lxml-xxe | package | Can lxml read local files through XML entities by default? | GHSA-vfmq-68hx-4jfw |
| pkg-pillow-webp | package | Is there a heap overflow in pillow's WebP decoding? | GHSA-j7hp-h8jx-5ppr |
| pkg-litellm-sqli | package | Does litellm have SQL injection when checking API keys? | GHSA-r75f-5x8p-qvmc |
| c-urllib3-proxy-redirect | concept | A redirect to another origin keeps the proxy login header | GHSA-34jh-p97f-mpxf |
| c-gunicorn-smuggling | concept | request smuggling in a Python WSGI server that lets attackers bypass endpoint restrictions | GHSA-w3h3-4rj7-4ph4 |
| c-jinja-sandbox | concept | escaping a template sandbox using the format method | GHSA-q2x7-8rv6-6q7h |
| c-setuptools-url | concept | installer tool runs shell commands hidden in a package download URL | GHSA-cx63-2mw6-8hw5 |
| c-sqlalchemy-groupby | concept | SQL injection through the group by parameter of an ORM | GHSA-38fc-9xqv-7f7q |
| c-scrapy-auth-redirect | concept | web crawler sends the Authorization header to a different domain after a redirect | GHSA-cw9j-q3vf-hrrv |
| c-urllib3-at-redos | concept | URL parsing becomes extremely slow when the address has lots of @ signs | GHSA-q2q7-5pp4-w6pg |
| c-langflow-validate | concept | remote code execution through a code validation endpoint that calls exec | GHSA-g22f-v6f7-2hrh |
| c-keras-deser | concept | loading a deep learning model file can run attacker code | GHSA-36fq-jgmw-4r9c |
| c-starlette-host | concept | a forged Host header changes the request path and bypasses path-based security checks | GHSA-86qp-5c8j-p5mr |
| c-llamaindex-image | concept | path traversal when encoding an image in an LLM framework | GHSA-2rhq-96q8-4vjq |
| c-django-password-hashes | concept | users without permission could see other accounts' password hashes in the admin | GHSA-6mx3-3vqg-hpp2 |
| c-gitpython-env | concept | adding a git remote with a crafted URL can leak environment variables | GHSA-94p4-4cq8-9g67 |
| c-werkzeug-entropy | concept | debugger PIN generated with too little randomness | GHSA-gq9m-qvpx-68hc |
| chat-what-cve | chat | What is a CVE? | (none) |
| chat-thanks | chat | thanks, that was helpful! | (none) |
| chat-hello | chat | hello there | (none) |
| chat-who | chat | what can you do for me? | (none) |

Steps: write tests → FAIL → implement → PASS → run `uv run python -m evals.retrieval_exam --target frozen` with the real embedder and Ollama; record the numbers as they come out (never estimated). If recall < 90%, look at each miss and fix the code (not the questions) unless the question itself is wrong (then log why). Commit `feat: retrieval exam with recall@5 and route accuracy`.

---

### Task 6: Log the day, update the spec, merge

- `docs/PROJECT_LOG.md`: D23–D27, Day 7 journal (what I did, learned, open questions, next), dashboard row for recall@5 with the real number, challenges table rows for anything real that went wrong, glossary entries for "router" / "recall@5" if missing.
- Spec: section 5.4 notes (package route top k by meaning, duplicates merged, MAL-/lower-case IDs, ambiguous package words); phase table row 3 ✅.
- `uv run pytest -q` and both exams green; merge `phase3-retrieval` into `main` (`--no-ff`), delete the branch.
