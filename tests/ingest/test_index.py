import chromadb

from cve_copilot.ingest.index import COLLECTION, MAX_DOC_CHARS, build_index, doc_text
from cve_copilot.ingest.models import Advisory, AffectedRange


def adv(id_, summary="sum", details="det", flagged=False):
    return Advisory(id=id_, summary=summary, details=details, published=None, modified=None,
                    cvss_vector=None, cvss_score=None, aliases=["CVE-1"],
                    ranges=[AffectedRange("django", "0", "1", None)], flagged=flagged)


def fake_embed(texts):
    return [[float(len(t)), 1.0, 0.0] for t in texts]


def test_doc_text_contains_id_aliases_packages_and_is_capped():
    text = doc_text(adv("GHSA-1", details="x" * 5000))
    assert text.startswith("GHSA-1")
    assert "CVE-1" in text and "django" in text and "sum" in text
    assert len(text) == MAX_DOC_CHARS


def test_build_index_stores_docs_with_metadata(tmp_path):
    n = build_index(tmp_path / "chroma", [adv("A"), adv("B", flagged=True)], fake_embed, batch_size=1)
    assert n == 2
    col = chromadb.PersistentClient(path=str(tmp_path / "chroma")).get_collection(COLLECTION)
    got = col.get(ids=["B"])
    assert got["metadatas"][0] == {"id": "B", "packages": "django", "flagged": 1}
    assert col.count() == 2
