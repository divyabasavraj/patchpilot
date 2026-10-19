import sqlite3
from contextlib import closing

import pytest

from cve_copilot.rag.models import Route
from cve_copilot.rag import retriever
from cve_copilot.rag.retriever import keyword_candidates, load_docs, package_names, retrieve
from cve_copilot.scanner.db import open_db

from .fixture_index import build_fixture, fake_embed


@pytest.fixture(scope="module")
def db_dir(tmp_path_factory):
    return build_fixture(tmp_path_factory.mktemp("rag") / "db")


def ask(route, question, db_dir, k=5):
    return retrieve(route, question, db_dir, k=k, embed_fn=fake_embed)


def test_id_lookup_by_main_id(db_dir):
    [doc] = ask(Route("id", ids=("GHSA-pin-1",)), "q", db_dir)
    assert (doc.id, doc.packages, doc.cvss_score, doc.score) == ("GHSA-pin-1", ("werkzeug",), 7.0, None)
    assert doc.affected == ("werkzeug: all versions before 0.15.3 (fixed in 0.15.3)",)


def test_cve_alias_lookup_merges_duplicates(db_dir):
    [doc] = ask(Route("id", ids=("CVE-2023-1",)), "q", db_dir)
    assert doc.id == "GHSA-sess-1"
    assert doc.aliases == ("CVE-2023-1", "PYSEC-2023-1")
    assert doc.summary == "Session cookie leaks into a shared cache"
    assert doc.affected == ("flask: all versions before 2.2.5 (fixed in 2.2.5)",)


def test_lookup_by_the_duplicate_gives_the_same_doc(db_dir):
    [doc] = ask(Route("id", ids=("PYSEC-2023-1",)), "q", db_dir)
    assert doc.id == "GHSA-sess-1"


def test_unknown_id_returns_nothing(db_dir):
    assert ask(Route("id", ids=("CVE-1999-0001",)), "q", db_dir) == []


def test_several_ids_keep_question_order(db_dir):
    docs = ask(Route("id", ids=("GHSA-pin-1", "CVE-2024-9999")), "q", db_dir)
    assert [d.id for d in docs] == ["GHSA-pin-1", "GHSA-sql-1"]


def test_kev_flag_comes_from_an_alias(db_dir):
    [doc] = ask(Route("id", ids=("GHSA-sql-1",)), "q", db_dir)
    assert doc.in_kev is True


def test_flag_and_affected_text_variants(db_dir):
    with closing(open_db(db_dir / "cve.db")) as con:
        flag, old, git = load_docs(con, ["GHSA-flag-1", "GHSA-old-1", "GHSA-git-1"])
    assert (flag.flagged, flag.flag_reason) == (True, "ignore-instructions")
    assert old.affected == ("oldlib: 1.0 and later versions up to and including 1.4 (no fix listed)",)
    assert git.affected == ("gitlib: versions 0.9, 1.0",)


def test_package_route_ranks_by_meaning(db_dir):
    docs = ask(Route("package", packages=("django",)), "sql problems", db_dir, k=2)
    assert [d.id for d in docs] == ["GHSA-sql-1", "GHSA-sql-2"] or \
           [d.id for d in docs] == ["GHSA-sql-2", "GHSA-sql-1"]
    assert all(d.score is not None for d in docs)


def test_package_route_puts_malware_first(db_dir):
    docs = ask(Route("package", packages=("reqeusts",)), "anything", db_dir)
    assert [d.id for d in docs] == ["MAL-2024-1", "GHSA-typo-1"]
    assert docs[0].score is None


def test_concept_route_merges_duplicates_and_respects_k(db_dir):
    docs = ask(Route("concept"), "session session", db_dir, k=3)
    ids = [d.id for d in docs]
    assert len(ids) == 3 and len(set(ids)) == 3
    assert "PYSEC-2023-1" not in ids and "GHSA-sess-1" in ids
    assert docs == sorted(docs, key=lambda d: -d.score)


def test_concept_route_finds_the_right_topic(db_dir):
    docs = ask(Route("concept"), "cross site", db_dir, k=1)
    assert docs[0].id == "GHSA-xss-1"


def test_chat_route_needs_no_database(tmp_path):
    assert retrieve(Route("chat"), "hi", tmp_path / "nothing") == []


def test_package_names(db_dir):
    names = package_names(db_dir / "cve.db")
    assert {"flask", "reqeusts", "gitlib"} <= names


def test_missing_db_says_build_it_first(tmp_path):
    with pytest.raises(FileNotFoundError, match="Build it first"):
        ask(Route("id", ids=("CVE-2023-1",)), "q", tmp_path)


def test_rare_shared_word_lifts_a_doc():
    from cve_copilot.rag.models import Doc
    from cve_copilot.rag.retriever import keyword_scores

    def doc(i, summary):
        return Doc(i, (), ("pillow",), summary, "", None, False, False, None, ())
    docs = [doc("A", "heap overflow in pillow"), doc("B", "heap overflow in pillow"),
            doc("C", "libwebp overflow in pillow")]
    scores = keyword_scores("heap overflow in pillow webp decoding", docs)
    assert scores["C"] > scores["A"] == scores["B"] > 0
    assert keyword_scores("the and of", docs) == {"A": 0.0, "B": 0.0, "C": 0.0}


def test_version_list_hidden_when_a_range_exists(tmp_path):
    from cve_copilot.ingest.models import Advisory, AffectedRange
    from cve_copilot.ingest.store import write_db
    adv = Advisory("PYSEC-x", "s", "", None, None, None, None,
                   ranges=[AffectedRange("lib", "0", "2.0", None)],
                   versions=[("lib", "1.0"), ("lib", "1.1"), ("other", "0.1")])
    write_db(tmp_path / "cve.db", [adv], [])
    with closing(open_db(tmp_path / "cve.db")) as con:
        [doc] = load_docs(con, ["PYSEC-x"])
    assert doc.affected == ("lib: all versions before 2.0 (fixed in 2.0)", "other: versions 0.1")


def test_range_words_never_need_working_out():
    from cve_copilot.rag.retriever import _range_words
    assert _range_words("0", "3.0.3", None) == "all versions before 3.0.3 (fixed in 3.0.3)"
    assert _range_words("2.0", "2.2.5", None) == "2.0 and later versions before 2.2.5 (fixed in 2.2.5)"
    assert _range_words("1.0", None, None) == "1.0 and later versions (no fixed version)"
    assert _range_words(None, None, None) == "all versions (no fixed version)"


def test_keyword_candidates_rank_by_bm25(db_dir):
    with closing(open_db(db_dir / "cve.db")) as con:
        assert keyword_candidates(con, "debugger pin guessable", 3)[0] == "GHSA-pin-1"
        assert keyword_candidates(con, "the and of", 3) == []      # only stopwords: no query
        assert "MAL-2024-1" not in keyword_candidates(con, "malicious reqeusts", 5)


def test_keyword_candidates_on_a_db_without_text_index(tmp_path):
    con = sqlite3.connect(tmp_path / "old.db")   # built before D49: no advisory_text table
    assert keyword_candidates(con, "debugger pin", 3) == []


def test_concept_route_adds_keyword_matches_meaning_missed(db_dir, monkeypatch):
    # The fake vectors know nothing of "debugger", so a meaning pool of 3 misses the pin doc;
    # the keyword match adds it to the docs that get re-ranked.
    pools = []
    real = retriever.load_docs
    monkeypatch.setattr(retriever, "load_docs", lambda con, ids: pools.append(list(ids)) or real(con, ids))
    monkeypatch.setattr(retriever, "CANDIDATES_PER_RESULT", 1)
    ask(Route("concept"), "session guessable debugger", db_dir, k=3)
    monkeypatch.setattr(retriever, "KEYWORD_CANDIDATES", 0)
    ask(Route("concept"), "session guessable debugger", db_dir, k=3)
    with_keywords, meaning_only = pools
    assert "GHSA-pin-1" not in meaning_only
    assert "GHSA-pin-1" in with_keywords
