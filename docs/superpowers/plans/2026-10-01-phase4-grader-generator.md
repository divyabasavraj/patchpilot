# Phase 4: Grader + Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn retrieved advisories into a cited, plain-English answer: grade what was found, rewrite the query and retry once if nothing is relevant, otherwise say "I couldn't find this", then generate an answer that cites IDs and only uses versions from the sources. Measure it with the `answers` exam (citation accuracy ≥ 98%, groundedness ≥ 90%).

**Architecture:** Four small modules in `src/cve_copilot/rag/`. `citations.py` pulls advisory IDs and version strings out of text (pure code; Phase 5's output guard reuses it). `grader.py` asks the LLM, in **one** JSON call, which documents are relevant, and can rewrite a query. `generator.py` builds the prompt (question + scanner facts + labelled sources) and calls the LLM. `pipeline.py` wires router → retriever → grader (→ rewrite → retriever → grader) → generator and records every step in a `Trace`. The CLI gains `--answer` and `--requirements`. `evals/answers_exam.py` scores answers with code checks plus an LLM groundedness judge.

**Tech Stack:** Python 3.12 (uv), the existing `llm.complete` interface (Ollama locally, fake in tests), pytest.

**Spec:** `docs/superpowers/specs/2026-09-26-cve-copilot-design.md` (sections 2, 5.4 grader + generator, 5.5 trace, 8, 9)

## Global Constraints

- Plain Python; no LangChain. Unit tests use `LLM=fake` and the fake embedder from `tests/rag/fixture_index.py`; no network, no real model.
- **Facts come from code.** Affected versions, fixes, CVSS and KEV reach the LLM only as text produced by code (`Doc.affected`, scanner facts). The LLM explains them.
- Retry at most **once** (one rewrite + one more retrieval) — spec 5.4.
- Not-found message, exactly: `I couldn't find this in the vulnerability database.`
- Pass marks: citation accuracy ≥ 98%, groundedness ≥ 90%.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions made while planning (log as D29–D33)

- **D29. One grading call for all documents, not one per document.** GitHub Models' free tier limits requests per day; five grading calls per question would use the CI budget five times faster. The grader sends ID + summary + the start of the details for each document and gets back `{"relevant": [IDs]}`. IDs it invents are ignored.
- **D30. id-route documents are not graded.** If the user names `CVE-2024-34069`, its advisory is relevant by definition; asking the LLM could only lose it. An unknown ID gives the not-found message directly (rewriting cannot find a missing ID).
- **D31. If the grader's reply is unusable, keep all documents.** Throwing away good retrieval because of a JSON mistake would turn a formatting problem into "I don't know". The trace records `grader_error`.
- **D32. Scanner facts are capped at 30 findings, most urgent first.** A requirements file can produce 60+ findings (Day 6 demo); the prompt must stay small for a 7B model. The facts say how many were left out.
- **D33. The answers exam scores four things, two with pass marks.** *Citation accuracy* (pass mark): share of IDs cited in answers that were among the sources given. *Groundedness* (pass mark): share of answers an LLM judge calls fully supported by the sources. Reported without a pass mark yet: *answer correctness* (cites an expected ID and mentions every expected version) and *version accuracy* (version strings in answers found in sources or facts). The judge is the same local model, a known weakness, logged.

## Review Focus

1. **The LLM cites an ID that was not in the sources** (e.g. copies a CVE from its memory) — the exam must count it as a citation error, not ignore it. Tested in Task 1 (`test_find_ids_in_answer_text`) and Task 5 (`test_citation_accuracy_counts_invented_ids`).
2. **Grader reply names an ID that was not retrieved** — must be ignored, not crash or add a document. Tested in Task 2 (`test_grader_ignores_unknown_ids`).
3. **Nothing relevant after the rewrite** — exactly one rewrite and the fixed not-found message, no generator call. Tested in Task 4 (`test_rewrite_once_then_not_found`).
4. **Chat route** (e.g. "thanks") — answer without retrieval or grading, and without sources. Tested in Task 4 (`test_chat_route_skips_search`).
5. **Version strings vs CVSS scores** — `7.5` is both a CVSS score and a version shape; version accuracy checks against the source text, which includes CVSS, so a score is not a false error. Tested in Task 1 (`test_versions_found_in_sources`).

---

## File map

| File | Responsibility |
|---|---|
| `src/cve_copilot/rag/citations.py` | `find_ids(text)`, `find_versions(text)`, `unsupported_versions(text, source_text)` |
| `src/cve_copilot/rag/grader.py` | `grade(question, docs, *, settings) -> Grades`, `rewrite_query(question, *, settings) -> str` |
| `src/cve_copilot/rag/generator.py` | `scan_facts(report) -> str`, `source_text(docs) -> str`, `generate(question, docs, facts, *, settings) -> str`, `chat_reply(question, *, settings) -> str` |
| `src/cve_copilot/rag/pipeline.py` | `Trace`, `Answer`, `answer(question, db_dir, *, report=None, k=5, embed_fn, settings) -> Answer` |
| `src/cve_copilot/rag/__main__.py` | `--answer`, `--requirements FILE` |
| `evals/data/answers.jsonl`, `evals/answers_exam.py` | Exam |
| `tests/rag/test_citations.py`, `test_grader.py`, `test_generator.py`, `test_pipeline.py`, `tests/evals/test_answers_exam.py` | Tests |

---

### Task 1: `citations.py` (pure code)

- `find_ids(text)`: reuses the router's ID regex and normalisation (`router.find_ids`), order of appearance, no repeats.
- `find_versions(text)`: `\b\d+(?:\.\d+)+(?:(?:a|b|rc|\.post|\.dev)\d+)?\b` — dotted numbers, optional pre/post/dev suffix.
- `unsupported_versions(text, source_text)`: versions in `text` that do not appear in `find_versions(source_text)`.
- Tests: `test_find_ids_in_answer_text` (brackets, lower-case GHSA, repeats), `test_find_versions` (`2.2.5`, `3.1.3rc1`, not `CVE-2024-34069`, not `2024-05-01`), `test_versions_found_in_sources` (CVSS `7.5` in sources is not unsupported; `9.9.9` is).
- Commit `feat: find cited IDs and version strings in answer text`.

### Task 2: Grader

- `Grades(relevant: list[Doc], verdicts: dict[str, bool], error: str | None)`.
- `grade`: empty docs → empty Grades without an LLM call. One `llm.complete(..., json_mode=True)` call; the user message lists each doc as `[ID] summary — details[:300]`. Parse `{"relevant": [...]}`; IDs matched against doc IDs **and aliases** (the model may cite the CVE), unknown ones ignored. Unusable reply → all docs relevant, `error="grader reply unusable"` (D31).
- `rewrite_query`: one plain-text call: "Rewrite this question as a short search query for a database of Python security advisories. Reply with the query only." Strip quotes/whitespace; empty reply → original question.
- Tests: relevant subset kept in original order; alias match; `test_grader_ignores_unknown_ids`; junk reply keeps all with error; no call for empty docs; rewrite strips quotes and falls back.
- Commit `feat: grader rates retrieved documents in one call and rewrites queries`.

### Task 3: Generator

- `source_text(docs)`: one block per doc:
  ```
  [GHSA-…] also known as: CVE-…, PYSEC-…
  Packages: flask | CVSS: 7.5 | Known exploited (CISA KEV): yes
  Affected: flask: from 0, fixed in 2.2.5; …
  Summary: …
  Details: … (first 1,200 characters)
  ```
- `scan_facts(report)`: header `Scan of the user's requirements file: N pinned packages checked, M findings.`; up to 30 findings `- flask 2.2.0: GHSA-… (CVSS 7.5, KEV, MALWARE) fixed in 2.2.5`; `(… and X more findings not shown)`; then `Suggested upgrades:` lines using the scanner's wording (`flask 2.2.0 -> 3.1.3`, `still affected by: …`, `no fixed version known`); `Not checked (not pinned): …`. `None` report → `""`.
- `generate`: system prompt with the rules (only use sources and scanner facts; cite IDs in square brackets after each claim; only use version numbers that appear in them; say clearly when the sources don't answer; never write exploit code or attack steps; plain English, at most about 200 words). User message: question, scanner facts (if any), sources.
- `chat_reply`: short system prompt (friendly; explain general terms simply; never state specific vulnerability facts, IDs or versions; suggest asking about a package, an advisory ID or uploading requirements).
- Tests: source block contents (KEV yes/no, aliases, truncation), scan facts cap and wording, prompt contains rules + sources + facts, chat prompt has no sources.
- Commit `feat: generator prompt with labelled sources and scanner facts`.

### Task 4: Pipeline + trace + CLI

- `Trace(route, retrieved, graded, rewritten_query=None, retrieved_after_rewrite=(), grader_error=None, outcome="")` — `retrieved`/`graded` are tuples of IDs; `outcome` ∈ `answered|not_found|chat`.
- `Answer(text, sources: list[Doc], trace: Trace)`.
- `answer()`:
  1. `route, docs = search(question, db_dir, …)`.
  2. chat → `chat_reply`, outcome `chat`, no sources.
  3. id route → no grading (D30); no docs → not-found message naming the IDs: `I couldn't find CVE-1999-0001 in the vulnerability database.`
  4. otherwise grade; nothing relevant → `rewrite_query`, `retrieve(route, rewritten, …)` (same route kind), grade again; still nothing → not-found message, outcome `not_found`.
  5. `generate(question, relevant, scan_facts(report))`, outcome `answered`, `sources = relevant`.
- CLI: `--answer` prints the answer, then `Sources:` (ID + summary) and a one-line trace; `--requirements FILE` scans it with the same target's DB and passes the report.
- Tests (fake LLM + fixture DB): `test_chat_route_skips_search`, `test_id_route_skips_grader`, `test_unknown_id_not_found_without_llm_generation`, `test_relevant_docs_go_to_generator`, `test_rewrite_once_then_not_found` (exactly 1 rewrite, 2 grading calls, 0 generation), `test_rewrite_finds_docs`, `test_scan_facts_reach_prompt`, CLI `--answer` output.
- Commit `feat: full answer pipeline with grading, one retry and a trace`.

### Task 5: `answers` exam

Item: `{"id", "question", "requirements"?: str, "expected_ids": [...] (any one cited counts; nested lists = alternatives as in Phase 3), "expected_versions": [...], "expect_not_found": bool}`.

Per item: run `answer()`; `cited = citations.find_ids(text)`; source names = IDs + aliases of `answer.sources` (plus scanner finding IDs/aliases when a report was given). Then:
- citation errors = cited IDs not in source names;
- correct = (expect_not_found and outcome == not_found) or (an expected ID cited and every expected version in the text);
- unsupported versions = `unsupported_versions(text, source_text(sources) + scan facts)`;
- groundedness: judge call (JSON `{"grounded": true|false, "reason": "..."}`) given sources + facts + answer, only for `answered` items; not-found and chat answers count as grounded.

Totals: `citation_accuracy` = 1 − errors / cited (1.0 if nothing cited), `groundedness`, `answer_correctness`, `version_accuracy`. `main()` exits 1 if citation accuracy < 0.98 or groundedness < 0.90.

20 items on frozen data: 4 id-route, 6 package-route, 5 concept, 3 with `requirements`, 2 expect-not-found. Expected IDs/versions are read from the advisory (`Doc.affected`) by hand, never from our generator.

Unit tests: `test_citation_accuracy_counts_invented_ids` (fake LLM answer citing a non-source ID), not-found item scoring, judge junk → counted as not grounded (strict), exit code.

Commit `feat: answers exam with citation accuracy and groundedness judge`.

### Task 6: Log, spec, merge

Same as Phase 3: D29–D33, Day 7 entry extended (Phase 4 part), dashboard rows for citation accuracy and groundedness (real numbers), challenges, spec 5.4 notes + phase row 4 ✅, merge `phase4-generator`.
