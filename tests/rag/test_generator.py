import dataclasses

from cve_copilot.config import Settings
from cve_copilot.llm import fake
from cve_copilot.rag.generator import (MAX_FACT_FINDINGS, chat_reply, generate, scan_facts,
                                       source_text)
from cve_copilot.rag.models import Doc
from cve_copilot.scanner.models import Finding, LineNote, Pin, ScanReport, Upgrade

FAKE = dataclasses.replace(Settings.from_env(), llm="fake")
DOC = Doc("GHSA-a", ("CVE-2023-1111", "PYSEC-2023-1"), ("flask",), "Cookie leak", "x" * 2000,
          7.5, True, False, None, ("flask: from 0, fixed in 2.2.5", "flask: from 2.3.0, fixed in 2.3.2"))


def finding(i, **kw):
    base = dict(package="flask", version="2.2.0", advisory_id=f"GHSA-{i}", aliases=(), records=(),
                summary="s", cvss_score=7.5, in_kev=False, is_malware=False,
                fixed_versions=("2.2.5",), upgrade_to="2.2.5")
    return Finding(**{**base, **kw})


def test_source_block():
    text = source_text([DOC])
    assert text.startswith("[GHSA-a] also known as: CVE-2023-1111, PYSEC-2023-1\n")
    assert "Packages: flask | CVSS: 7.5 | Known exploited (CISA KEV): yes" in text
    assert "Affected: flask: from 0, fixed in 2.2.5; flask: from 2.3.0, fixed in 2.3.2" in text
    assert "Summary: Cookie leak" in text
    assert "x" * 1200 in text and "x" * 1201 not in text


def test_source_block_without_score_or_aliases():
    d = dataclasses.replace(DOC, aliases=(), cvss_score=None, in_kev=False, affected=())
    text = source_text([d])
    assert text.startswith("[GHSA-a]\n")
    assert "CVSS: unknown | Known exploited (CISA KEV): no" in text
    assert "Affected: unknown" in text


def test_scan_facts_wording_and_cap():
    findings = [finding("kev", in_kev=True, cvss_score=5.0), finding("mal", is_malware=True,
                cvss_score=None, fixed_versions=(), upgrade_to=None)]
    findings += [finding(f"x{i}") for i in range(MAX_FACT_FINDINGS)]
    report = ScanReport(findings=findings, checked=[Pin("flask", "2.2.0", 1, "flask==2.2.0")],
                        not_pinned=[LineNote(2, "requests", "not pinned")], skipped=[],
                        upgrades={"flask": Upgrade("3.1.3", ())})
    text = scan_facts(report)
    assert text.startswith("Scan of the user's requirements file: 1 pinned packages checked, "
                           f"{MAX_FACT_FINDINGS + 2} findings.")
    assert "- flask 2.2.0: GHSA-kev (CVSS 5.0, KEV) fixed in 2.2.5" in text
    assert "- flask 2.2.0: GHSA-mal (CVSS unknown, MALWARE) no fixed version known" in text
    assert "(and 2 more findings not shown)" in text
    assert "flask 2.2.0 -> 3.1.3" in text
    assert "Not checked (not pinned): requests" in text


def test_no_report_no_facts():
    assert scan_facts(None) == ""


def test_generate_prompt_has_rules_sources_and_facts():
    fake.set_responses(["answer [GHSA-a]"])
    assert generate("is flask ok?", [DOC], "Scan of ...", settings=FAKE) == "answer [GHSA-a]"
    system, user = (m["content"] for m in fake.calls[0]["messages"])
    assert "square brackets" in system and "version" in system and "exploit" in system
    assert user.startswith("Question: is flask ok?")
    assert "Scanner facts:\nScan of ..." in user and "[GHSA-a] also known as" in user


def test_chat_reply_has_no_sources():
    fake.set_responses(["Hi!"])
    assert chat_reply("hello", settings=FAKE) == "Hi!"
    system, user = (m["content"] for m in fake.calls[0]["messages"])
    assert user == "hello" and "never" in system.lower()
