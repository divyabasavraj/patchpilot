import dataclasses
import json

import pytest

from cve_copilot.config import Settings
from cve_copilot.llm import fake
from cve_copilot.rag.router import find_ids, find_packages, route_question

KNOWN = {"flask", "django", "mcp-atlassian", "keep", "black", "pip", "requests"}
FAKE = dataclasses.replace(Settings.from_env(), llm="fake")


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
    assert find_packages("I installed it with pip", KNOWN) == ()


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
