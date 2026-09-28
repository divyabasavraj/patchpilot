import json

from cve_copilot.ingest.snapshot import filter_kev, select_snapshot


def f(id_, pkg, aliases=()):
    rec = {"id": id_, "aliases": list(aliases),
           "affected": [{"package": {"name": pkg, "ecosystem": "PyPI"}}]}
    return f"{id_}.json", json.dumps(rec).encode()


FILES = [f("A", "Django"), f("B", "flask"), f("C", "other1"), f("D", "other2"),
         f("E", "other3"), ("bad.json", b"{oops")]


def test_keeps_all_target_packages_plus_distractors():
    got = select_snapshot(FILES, {"django", "flask"}, n_distractors=2)
    names = [n for n, _ in got]
    assert "A.json" in names and "B.json" in names
    assert len(names) == 4
    assert names == sorted(names)
    assert "bad.json" not in names


def test_is_deterministic():
    assert select_snapshot(FILES, {"django"}, 2) == select_snapshot(FILES, {"django"}, 2)


def test_filter_kev_keeps_shape():
    kev = {"title": "t", "vulnerabilities": [{"cveID": "CVE-1"}, {"cveID": "CVE-2"}]}
    assert filter_kev(kev, {"CVE-2"}) == {"title": "t", "vulnerabilities": [{"cveID": "CVE-2"}]}
