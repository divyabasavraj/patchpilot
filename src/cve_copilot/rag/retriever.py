"""Fetch the advisories that answer a routed question (spec 5.4).

id route: exact lookup by ID or alias. package route: that package's advisories, ranked by
meaning (D26). concept route: Chroma search plus the best keyword (BM25) matches (D49).
Duplicate records of one bug become one Doc (D24).
"""
import math
import re
import sqlite3
from collections import defaultdict
from collections.abc import Callable, Iterable
from contextlib import closing
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import chromadb
import numpy as np

from ..embeddings import embed
from ..ids import group_ids, main_id
from ..ingest.index import COLLECTION
from ..scanner.db import open_db
from .models import Doc, Route

EmbedFn = Callable[[list[str]], list[list[float]]]
MAX_LISTED_VERSIONS = 12   # explicit version lists can be hundreds long
CANDIDATES_PER_RESULT = 4   # concept route: fetch 4 x k by meaning, then re-rank down to k
KEYWORD_WEIGHT = 0.2       # hybrid re-rank: meaning score + 0.2 x keyword score (D28)
KEYWORD_CANDIDATES = 10    # concept route: also re-rank the 10 best keyword matches (D49)
_STOPWORDS = frozenset("""
    the and for are was were with that this from can does did has have how what when where which
    who why will would could should there their they them then than into onto about any all
    not but use used using via its it's your you yours my our is be been being""".split())


@lru_cache(maxsize=4)
def package_names(db_path: Path) -> frozenset[str]:
    with closing(open_db(db_path)) as con:
        return frozenset(row[0] for row in con.execute(
            "SELECT package FROM affected UNION SELECT package FROM affected_versions"))


@lru_cache(maxsize=4)
def _collection(chroma_dir: str):
    return chromadb.PersistentClient(path=chroma_dir).get_collection(COLLECTION)


def _in(column: str, values: list[str]) -> tuple[str, list[str]]:
    return f"{column} IN ({','.join('?' * len(values))})", values


def _aliases(con: sqlite3.Connection, ids: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    if ids:
        where, args = _in("advisory_id", ids)
        for adv_id, alias in con.execute(f"SELECT advisory_id, alias FROM aliases WHERE {where}", args):
            out[adv_id].append(alias)
    return out


def _records_for(con: sqlite3.Connection, ids: list[str]) -> list[str]:
    """Stored records with these IDs or aliases, plus their duplicates (the whole group)."""
    found: set[str] = set()
    frontier = set(ids)
    while frontier:
        names = sorted(frontier)
        where_id, args = _in("id", names)
        where_alias, _ = _in("alias", names)
        new = {r[0] for r in con.execute(f"SELECT id FROM advisories WHERE {where_id}", args)}
        new |= {r[0] for r in con.execute(f"SELECT advisory_id FROM aliases WHERE {where_alias}", args)}
        new -= found
        found |= new
        frontier = {a for als in _aliases(con, sorted(new)).values() for a in als} | new
        frontier -= set(names)
    return sorted(found)


def _range_words(intro: str | None, fixed: str | None, last: str | None) -> str:
    """Say a range in words the LLM can copy as they are: "before 3.0.3", never a version it
    would have to work out itself, such as "up to 3.0.2" (D43)."""
    start = "" if intro in (None, "", "0") else f"{intro} and later "
    if fixed:
        return f"{start or 'all '}versions before {fixed} (fixed in {fixed})"
    if last:
        return f"{start or 'all '}versions up to and including {last} (no fix listed)"
    return f"{start or 'all '}versions (no fixed version)"


def _affected_text(con: sqlite3.Connection, ids: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    where, args = _in("advisory_id", ids)
    for adv_id, pkg, intro, fixed, last in con.execute(
            f"SELECT advisory_id, package, introduced, fixed, last_affected FROM affected "
            f"WHERE {where} ORDER BY rowid", args):
        out[adv_id].append(f"{pkg}: {_range_words(intro, fixed, last)}")
    ranged = {(adv_id, t.split(":", 1)[0]) for adv_id, texts in out.items() for t in texts}
    listed: dict[tuple[str, str], list[str]] = defaultdict(list)
    for adv_id, pkg, version in con.execute(
            f"SELECT advisory_id, package, version FROM affected_versions WHERE {where} "
            f"ORDER BY rowid", args):
        listed[(adv_id, pkg)].append(version)
    for (adv_id, pkg), versions in listed.items():
        if (adv_id, pkg) in ranged:
            continue   # ranges already say it; long version lists only add noise to the prompt
        shown = ", ".join(versions[:MAX_LISTED_VERSIONS])
        more = len(versions) - MAX_LISTED_VERSIONS
        out[adv_id].append(f"{pkg}: versions {shown}" + (f" (and {more} more)" if more > 0 else ""))
    return out


def load_docs(con: sqlite3.Connection, ids: Iterable[str]) -> list[Doc]:
    """One Doc per bug for the given IDs or aliases, in the order they were asked for."""
    wanted = list(dict.fromkeys(ids))
    records = _records_for(con, wanted) if wanted else []
    if not records:
        return []
    where, args = _in("id", records)
    rows = {r[0]: r for r in con.execute(
        f"SELECT id, summary, details, cvss_score, flagged, flag_reason FROM advisories WHERE {where}",
        args)}
    aliases = _aliases(con, records)
    affected = _affected_text(con, records)
    every_id = sorted(set(records) | {a for als in aliases.values() for a in als})
    where_kev, kev_args = _in("cve_id", every_id)
    kev = {r[0] for r in con.execute(f"SELECT cve_id FROM kev WHERE {where_kev}", kev_args)}
    packages: dict[str, set[str]] = defaultdict(set)
    where_pkg, _ = _in("advisory_id", records)
    for table in ("affected", "affected_versions"):
        for adv_id, pkg in con.execute(f"SELECT advisory_id, package FROM {table} WHERE {where_pkg}",
                                       args):
            packages[adv_id].add(pkg)

    position = {name: i for i, name in enumerate(wanted)}
    docs = []
    for group in group_ids((r, aliases[r]) for r in records):
        names = set(group) | {a for r in group for a in aliases[r]}
        top = main_id(group)
        ordered = [top] + [r for r in group if r != top]
        scores = [rows[r][3] for r in group if rows[r][3] is not None]
        reasons = [rows[r][5] for r in group if rows[r][4] and rows[r][5]]
        docs.append((min(position.get(n, len(position)) for n in names), Doc(
            id=top,
            aliases=tuple(sorted(names - {top})),
            packages=tuple(sorted(set().union(*(packages[r] for r in group)))),
            summary=next(((rows[r][1] or "").strip() for r in ordered if (rows[r][1] or "").strip()), ""),
            details=next(((rows[r][2] or "").strip() for r in ordered if (rows[r][2] or "").strip()), ""),
            cvss_score=max(scores) if scores else None,
            in_kev=bool(names & kev),
            flagged=any(rows[r][4] for r in group),
            flag_reason="; ".join(dict.fromkeys(reasons)) or None,
            affected=tuple(dict.fromkeys(t for r in ordered for t in affected[r])),
        )))
    return [doc for _, doc in sorted(docs, key=lambda pair: pair[0])]


def _terms(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) >= 3 and w not in _STOPWORDS}


def _hits(words: set[str], doc_words: set[str]) -> set[str]:
    """Question words in the doc; words of 4+ letters also match inside longer ones (webp, libwebp)."""
    return {w for w in words if w in doc_words or (len(w) >= 4 and any(w in dw for dw in doc_words))}


def keyword_scores(question: str, docs: list[Doc]) -> dict[str, float]:
    """0..1 per doc: share of the question's word weight found in the doc, rare words weighing most."""
    words = _terms(question)
    doc_words = {d.id: _hits(words, _terms(" ".join([d.id, *d.aliases, d.summary, d.details])))
                 for d in docs}
    n = len(docs)
    idf = {}
    for w in words:
        df = sum(w in ws for ws in doc_words.values())
        idf[w] = math.log(1 + (n - df + 0.5) / (df + 0.5))
    total = sum(idf.values())
    if not total:
        return {d.id: 0.0 for d in docs}
    return {d.id: sum(idf[w] for w in doc_words[d.id]) / total for d in docs}


def _rerank(question: str, docs: list[Doc], k: int) -> list[Doc]:
    """Hybrid order: meaning score plus a keyword bonus; unindexed docs (score None) first."""
    kw = keyword_scores(question, docs)
    ranked = sorted(docs, key=lambda d: (d.score is not None,
                                         -((d.score or 0.0) + KEYWORD_WEIGHT * kw[d.id])))
    return ranked[:k]


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b)))


def keyword_candidates(con: sqlite3.Connection, question: str,
                       n: int = KEYWORD_CANDIDATES) -> list[str]:
    """IDs of the n best full-text (BM25) matches for the question's words. Empty for a DB
    built before D49, which has no advisory_text table."""
    words = sorted(_terms(question))
    if not words or n <= 0:
        return []
    query = " OR ".join(f'"{w}"' for w in words)
    try:
        return [r[0] for r in con.execute(
            "SELECT id FROM advisory_text WHERE advisory_text MATCH ? "
            "ORDER BY bm25(advisory_text) LIMIT ?", (query, n))]
    except sqlite3.OperationalError:
        return []


def _scored(col, qvec: np.ndarray, docs: list[Doc], sims: dict[str, float]) -> list[Doc]:
    """Each doc with its best meaning score over its IDs; None when none of them is indexed."""
    missing = sorted({n for d in docs for n in (d.id, *d.aliases)} - set(sims))
    if missing:
        got = col.get(ids=missing, include=["embeddings"])
        sims = sims | {i: _cosine(qvec, np.asarray(v)) for i, v in zip(got["ids"], got["embeddings"])}
    scored = []
    for d in docs:
        hits = [sims[n] for n in (d.id, *d.aliases) if n in sims]
        scored.append(replace(d, score=max(hits) if hits else None))
    return scored


def _by_package(con, col, packages: tuple[str, ...], question: str, qvec: np.ndarray,
                k: int) -> list[Doc]:
    where, args = _in("package", list(packages))
    ids = sorted({r[0] for r in con.execute(
        f"SELECT advisory_id FROM affected WHERE {where} "
        f"UNION SELECT advisory_id FROM affected_versions WHERE {where}", args + args)})
    # Not indexed (malware, D11) first: a malicious package matters more than any bug.
    return _rerank(question, _scored(col, qvec, load_docs(con, ids), {}), k)


def _by_meaning(con, col, question: str, qvec: np.ndarray, k: int) -> list[Doc]:
    n = min(CANDIDATES_PER_RESULT * k, col.count())
    if n == 0:
        return []
    hits = col.query(query_embeddings=[qvec.tolist()], n_results=n, include=["distances"])
    sims = {i: 1.0 - dist for i, dist in zip(hits["ids"][0], hits["distances"][0])}
    # Meaning search blurs exact words ("debugger PIN"); keyword matches join the pool (D49).
    ids = list(dict.fromkeys(hits["ids"][0] + keyword_candidates(con, question, KEYWORD_CANDIDATES)))
    scored = [d for d in _scored(col, qvec, load_docs(con, ids), sims) if d.score is not None]
    return _rerank(question, scored, k)


def retrieve(route: Route, question: str, db_dir: Path, *, k: int = 5,
             embed_fn: EmbedFn = embed) -> list[Doc]:
    if route.kind == "chat":
        return []
    with closing(open_db(db_dir / "cve.db")) as con:
        if route.kind == "id":
            return load_docs(con, route.ids)
        col = _collection(str(db_dir / "chroma"))
        qvec = np.asarray(embed_fn([question])[0])
        if route.kind == "package":
            return _by_package(con, col, route.packages, question, qvec, k)
        if route.kind == "concept":
            return _by_meaning(con, col, question, qvec, k)
    raise ValueError(f"Unknown route kind: {route.kind!r}")
