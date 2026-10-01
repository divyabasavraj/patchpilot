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
