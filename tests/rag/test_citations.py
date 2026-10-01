from cve_copilot.rag.citations import find_ids, find_versions, unsupported_versions


def test_find_ids_in_answer_text():
    text = "Flask leaks cookies [GHSA-m2qf-hxjv-5gpq] (see ghsa-M2QF-hxjv-5gpq, CVE-2023-30861)."
    assert find_ids(text) == ("GHSA-m2qf-hxjv-5gpq", "CVE-2023-30861")


def test_find_versions():
    text = "Upgrade from 2.2.0 to 2.2.5 or 3.1.3rc1 (CVE-2024-34069, added 2024-05-01, v 10)."
    assert find_versions(text) == ("2.2.0", "2.2.5", "3.1.3rc1")


def test_versions_found_in_sources():
    sources = "flask: from 0, fixed in 2.2.5 | CVSS: 7.5"
    assert unsupported_versions("CVSS 7.5, fixed in 2.2.5, try 9.9.9.", sources) == ("9.9.9",)
