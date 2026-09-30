# CVE Copilot — Project Log

A daily record of building this project: what I built, why I made each decision, what went wrong, and what I learned. Written for interview prep: every section should help me explain the project out loud.

**How to use this log**
- **Daily journal**: one entry per work day, newest at the top.
- **Decision log**: every important choice, with the options I rejected and why.
- **Interview prep**: pitches, likely questions, and answers that grow as the project grows.

---

## 1. The pitch

### 30-second version
> Security scanners tell you *what* is wrong: a list of vulnerability IDs. My CVE Copilot explains *why it matters* and *how to fix it*, in plain English, with a source for every claim. It's a dynamic RAG system: it decides for each question whether to look something up, where to look, and whether what it found is good enough. A tested guardrail agent stops it from making things up or writing attack code, and CI runs an exam on every code change and every night's new data, so I can prove it with numbers.

### 2-minute version
1. **Problem:** AI assistants make things up. In 2024 a tribunal held Air Canada responsible after its chatbot invented a refund policy. In security, a made-up "fix version" leaves you exposed while thinking you're safe.
2. **What it does:** upload a Python `requirements.txt`, then see which packages have known vulnerabilities, how urgent each one is, and which version fixes it. Then chat about it.
3. **Key design idea:** *Facts come from code, explanations come from the AI.* Version matching is plain code that can't hallucinate. The AI only explains, and a guard checks the explanation against the facts.
4. **Dynamic RAG:** a router picks the route (exact ID lookup / package lookup / meaning search / no search). A grader checks whether the results are good enough, and if not it rewrites the search and retries, or says "I don't know."
5. **Evaluated guardrails:** three checkpoints (question, documents, answer). The guard has its own exam: how many attacks it blocks, and how many normal questions it wrongly blocks.
6. **CI:** code changes are tested on frozen data; data changes are tested on frozen code. New data only goes live if it passes the exam.
7. **Free and local:** runs on a free model on my laptop (Ollama); CI uses GitHub Models' free tier.

---

## 2. Glossary: explain it simply

### Security basics
| Term | Plain meaning |
|---|---|
| **Vulnerability** | A bug in software that attackers could abuse, like a broken lock on a door. |
| **CVE** | An official ID number for a known vulnerability, e.g. `CVE-2021-44228` (Log4Shell). The case number for the broken lock. |
| **GHSA / PYSEC** | Other ID systems for the same thing (GitHub advisories / Python advisories). One bug can have several IDs, called *aliases*. |
| **Patch / fixed version** | The newer version of the software where the lock is repaired. |
| **Affected range** | The versions that have the bug, e.g. "from 2.0 up to (not including) 2.3.1". |
| **Dependency** | Someone else's package that your project uses. Listed in `requirements.txt`. |
| **CVSS score** | Severity from 0 to 10. High means serious *if* exploited. |
| **CISA KEV** | The US government's list of vulnerabilities attackers are **actively using right now**, a strong "fix this first" signal. |
| **Exploit** | Code that actually uses a vulnerability to attack. My copilot refuses to write these. |
| **OSV.dev** | A free Google database of vulnerabilities in open-source packages. My main data source. |

### AI / RAG basics
| Term | Plain meaning |
|---|---|
| **RAG** | The AI looks things up in documents before answering, like an open-book exam. |
| **Dynamic RAG** | The AI *decides* how to look things up (whether, where, how often) instead of following one fixed routine. |
| **Embedding** | Turning text into numbers so we can search by meaning, not just exact words. |
| **Vector store** | A database that searches those number-versions of text (I use Chroma). |
| **Router** | The step that decides which route a question takes. |
| **Corrective RAG (CRAG)** | Grade what search found; if it's weak, search again differently or admit "I don't know". |
| **Hallucination** | The AI stating something false with confidence. |
| **Groundedness** | Whether every claim in the answer is supported by the retrieved sources. |
| **Prompt injection** | Hidden instructions trying to trick the AI, e.g. "ignore your rules". They can be in the user's question or hidden inside a document. |
| **Guardrail** | A safety check before or after the AI runs. |
| **Eval / golden set** | An exam: questions with known correct answers, used to score the system. |
| **CI** | Automatic testing that runs every time the code changes. |
| **Recall@k** | "Did the right document show up in the top k search results?" |
| **False-block rate** | How often the guard wrongly refuses a normal, safe question. |

---

## 3. Architecture

```
                         ┌──────────────────────── RUNTIME ────────────────────────┐
 requirements.txt ──► [Scanner: version math, no AI] ──► facts (affected? fixed in?)
                                                              │
 User question ──► [Input guard] ──► [Router] ──► [Retriever] ──► [Context guard] ──► [Generator] ──► [Output guard] ──► Answer + sources
                   attack? trick?    ID / package /  SQLite +        drop flagged      local or          cited IDs real?
                   off-topic?        concept / chat  Chroma          docs              GitHub model      versions in sources?
                                                        ▲                                                 grounded? no exploit?
                                                        └──────────── retry once, else "I don't know" ◄──────────┘
                         └─────────────────────────────────────────────────────────┘

 CI (GitHub Actions)
   • On every code change: exam on FROZEN data   → score report → pass/fail
   • Every night:          exam on NEW data      → go live only if it passes, else open an issue
```

| Folder | Job |
|---|---|
| `ingest/` | Download OSV + CISA KEV, store in SQLite + Chroma, scan documents for hidden instructions |
| `scanner/` | Read `requirements.txt`, compare versions against affected ranges |
| `rag/` | Router, retriever, grader, generator |
| `guards/` | Input, context, and output checks |
| `llm/` | One switch: `LLM=ollama` or `LLM=github` |
| `evals/` | Test sets, scoring, pass marks (`thresholds.yaml`) |
| `app.py` | Streamlit web app: upload tab + chat tab |

---

## 4. Decision log

Format: **what I decided → options considered → why → trade-off.** These make strong interview answers ("tell me about a technical decision you made").

### D1. Topic: CVE copilot for Python dependencies (2026-09-25)
- **Options:** CVE copilot, stock-filings analyst, medicine safety assistant, renter-rights helper.
- **Why:** it's the topic where all three ideas are really needed. The data changes daily (dynamic), mistakes are costly (guard), and answers are checkable (evals).
- **Trade-off:** I was new to security, so I had to learn the domain basics (see glossary).

### D2. Python, plain code instead of a big framework (2026-09-25)
- **Options:** LangChain/LangGraph, LlamaIndex, plain Python.
- **Why:** I can explain every line; each part (router, grader, guard) is a small file that can be tested alone.
- **Trade-off:** more code to write myself. I can move to LangGraph later if needed.

### D3. Facts from code, explanations from the AI (2026-09-25)
- **Why:** "Is version X affected?" is a math question, and code can't hallucinate math. The AI only explains; the guard checks that every version number it mentions exists in the sources.
- **Trade-off:** the answer is limited to what the database knows. That's intended: saying "not in the database" is the correct behaviour.

### D4. Free models only: Ollama locally, GitHub Models in CI (2026-09-25)
- **Options:** paid API; local only; local + GitHub Models.
- **Why:** zero cost. My Mac (M5, 16 GB) runs Qwen 2.5 7B quickly. GitHub's free CI machines have no graphics chip, so running a model *on them* is very slow; instead, CI sends questions to GitHub Models' servers.
- **Trade-off:** the CI model differs from the local model, and GitHub Models has daily free limits. The exam size is kept small (~100–150 questions).
- **Interview line:** *"The system is model-agnostic: one setting switches between a local and a hosted model."*

### D5. Same embedding model everywhere: fastembed (2026-09-25)
- **Why:** search results must be identical on my Mac and in CI, or the scores aren't comparable. fastembed runs on a normal processor, so it's fine on weak CI machines.

### D6. Code changes tested on frozen data; data changes tested on frozen code (2026-09-25)
- **Why:** if both change at once and the score drops, you can't tell which one caused it. Keeping one side fixed makes every score change explainable.
- **Standout feature:** new nightly data only goes live if it passes the exam. Most systems test code, not data.

### D7. Python 3.12 via `uv` (2026-09-25)
- **Why:** my system Python is 3.14, which is too new for some AI libraries. `uv` installs 3.12 just for this project without touching the rest of my setup.

### D8. Router uses rules first, the AI only as a fallback (2026-09-26)
- **Options:** always ask the AI which route to take; rules only; rules first, then the AI.
- **Why:** questions containing an ID like `CVE-2021-44228`, or a known package name, can be routed with a simple pattern check. It's instant, free, and never wrong. The AI is only asked for vague questions.
- **Trade-off:** the rules need maintaining, but they're small and unit-tested.

### D9. Unpinned requirements are reported, not guessed (2026-09-26)
- **Why:** `django>=3.0` could mean many versions. Guessing one would break the "facts from code" rule, so the scanner says "not checked: not pinned".

### D10. A small frozen data snapshot is committed for PR CI (2026-09-26)
- **Why:** PR exams need identical data every run (D6). I commit a small set of raw advisory files (<10 MB) covering the exam packages plus ~500 distractors, instead of the full database.

### D11. Malware records kept in the database, left out of meaning search (2026-09-27)
- **Why:** 11,785 of the 25,742 OSV PyPI records (46%) are `MAL-` records: fake packages uploaded to trick people. The scanner should still warn "this package is malware", so they stay in SQLite. Their text is near-identical boilerplate ("Malicious code in X"), so in Chroma they would crowd out real explanations.

### D12. Only PyPI packages and ECOSYSTEM version ranges are stored (2026-09-27)
- **Why:** some Python advisories also list npm/NuGet/Maven packages, and some ranges are Git commit hashes. Neither can be compared with a pip version. Explicit version lists are always kept.

### D13. CVSS preference: v3, then v4, then v2 (2026-09-27)
- **Why:** v3 is the most common (~9.6k records), so scores are comparable across advisories.

### D14. Frozen snapshot packages are chosen for feature coverage (2026-09-29)
Besides the packages the exams ask about, the snapshot deliberately includes packages with KEV-listed CVEs and with injection-flagged advisories, so CI can test the KEV badge and the injection guard. Random distractors alone gave 1 KEV entry and 0 flagged docs.

### D15. Duplicate advisories are merged into one finding (2026-09-29)
- **What:** the OSV PyPI export stores most bugs twice, as a GitHub advisory (`GHSA-`) and a PyPA one (`PYSEC-`) that list each other as aliases (16,990 alias rows). Records that share any ID or alias form one group = one finding. The main ID prefers GHSA, then PYSEC; `records` lists which stored advisories matched.
- **Why:** otherwise Flask 2.2.0 shows CVE-2023-30861 twice.

### D16. Malware findings sort first, above KEV (2026-09-29)
- **Why:** a `MAL-` advisory means the package itself is malicious (usually a typo-squat like `reqeusts`). That beats any bug, and it has no CVSS score, so "KEV, then CVSS" would put it last.

### D17. Environment markers are not evaluated (2026-09-29)
- **What:** `pywin32==300; sys_platform == "win32"` is still checked.
- **Why:** we don't know the user's platform, and a missed vulnerability is worse than one extra row.

### D18. One suggested upgrade per package, honest about what remains (2026-09-29)
- **What:** each vulnerable package gets one suggested upgrade: the fixed version hit by the fewest known advisories (final releases before pre-releases, ties go to the lowest). If some advisories still affect it, the scanner lists them ("still affected by: ...") instead of calling the upgrade safe. No fix at all gives "no fixed version known".
- **Why:** the fix for one bug can land inside another bug's range. Plan first said "safe upgrade"; the final review showed that word can be false.

### D19. The exam's expected answers come from the OSV.dev API (2026-09-29)
- **Why:** if our own scanner made the answers, the exam could never fail. `api.osv.dev/v1/querybatch` does its own version matching; the generator keeps only IDs that are in the frozen snapshot and not withdrawn.

### D20. Unreadable version bounds are salvaged, not dropped (2026-09-29)
- **What:** some advisory bounds are not valid versions (e.g. `4.1.0-NA`, `2.6.0-cu124`). We read the leading number (4.1.0, 2.6.0). With no number, an unreadable start counts as 0 and an unreadable end as "no end" (still affected). The finding carries a note ("advisory version '4.1.0-NA' is not a valid version; read as 4.1.0").
- **Why:** first version ignored such ranges, which silently missed real bugs (pynetbox 4.0.0, torch 2.5.0). An extra row with a label beats a silent miss.

### D21. The malware flag comes from the whole group (2026-09-29)
- **What:** a finding is malware if any record ID or alias in its group starts with `MAL-`.
- **Why:** when `MAL-2026-2144` was grouped with `PYSEC-2026-2`, the flag was lost (litellm 1.82.7).

### D22. Exam pins are hand-written, flags are independent (2026-09-29)
- **What:** each exam case lists its expected pins by hand, and the answer key (OSV.dev API plus raw KEV and snapshot files for the malware/KEV flags) never uses our parser or scanner. The generator fails if the parser disagrees with the hand-written pins.
- **Why:** pins taken from our own parser meant a parser bug would also change the answer key and the exam would still pass.

---

## 5. Daily journal

*Newest entry first. One entry per work day.*

### Day 6 — 2026-09-30: Phase 2 finished (scanner)
**What I did**
- Re-ran everything on the final reviewed code. `uv run pytest -q`: **123 passed**. Exam (`uv run python -m evals.scan_exam --target frozen`): **26/26 cases, accuracy 100%**, no failures.
- Updated the spec (section 5.2 and the phase table), the decision log (D15 to D22) and the results dashboard.
- Demo on the live database (`uv run python -m cve_copilot.scanner demo-requirements.txt --target live`), first rows, sorted KEV first then CVSS high to low (`urllib3` has no version, so it is listed as not checked; `-r base.txt` is skipped):

```
Checked 5 pinned packages: 62 findings in 4 packages.

PACKAGE                VERSION      ADVISORY               CVSS  FLAG     FIX
pillow                 10.0.0       GHSA-j7hp-h8jx-5ppr     8.8  KEV      10.0.1
django                 3.2.0        GHSA-2gwj-7jmv-h26r     9.8           3.2.13
django                 3.2.0        GHSA-p64x-8rxx-wf6q     9.8           3.2.14
django                 3.2.0        GHSA-r3xc-prgr-mg9p     9.8           3.2.19
django                 3.2.0        GHSA-w24h-v9qh-8gxj     9.8           3.2.13
django                 3.2.0        GHSA-xpfp-f569-q3p2     9.8           3.2.5
django                 3.2.0        GHSA-frmv-pr5f-9mcr     9.1           4.2.26
...
Suggested upgrades:
  flask 2.2.0 -> 3.1.3
  django 3.2.0 -> 5.2.17
  requests 2.19.0 -> 2.33.0
  pillow 10.0.0 -> 12.3.0

Not checked:
  line 6: urllib3  (not pinned)

Skipped:
  line 7: -r base.txt  (pip option -r)
```

**What I learned**
- Real data is messier than the docs say: some advisory version bounds are not versions at all (`4.1.0-NA`). Code that quietly skips what it cannot read turns into a scanner that quietly misses bugs.
- An exam only tests something if its answer key is independent. Mine used our own parser for the pins, so a parser bug would have hidden itself.
- A word like "safe" in a security tool must be true. "Suggested upgrade, still affected by X" is honest.

**Open questions**
- Should `!=` pins and environment markers be handled later? (Both are deliberately simple for now.)

**Next**
- Phase 3: retrieval + router (find the right advisories by meaning, decide which question type it is).

### Day 5 — 2026-09-29: Phase 1 merged, Phase 2 built and reviewed
**What I did**
- Did a final code review of the whole Phase 1 branch before merging. Findings:
  - **Frozen CI data was too thin:** only 1 KEV entry and 0 injection-flagged advisories. Later phases (KEV badge, Phase 5 guard) would have had nothing to test in CI. Added 5 packages to `data/frozen/packages.txt` on purpose: `starlette`, `litellm`, `langflow` (have KEV-listed CVEs) and `langroid`, `mcp-atlassian` (have flagged advisories). Picked them by querying the live database for packages with KEV hits, preferring small ones.
  - A `null` summary in an OSV record would have crashed the whole build (the injection scan ran outside the "skip malformed" guard). 0 such records exist today; fixed anyway, with a test.
  - A broken CVSS v3 string used to hide a valid v4 score; now it falls through to the next version, with a test.
- Rebuilt the frozen snapshot (numbers from `data/frozen/db/manifest.json`):

  | Raw files | Advisories | Withdrawn | Malformed | Malware | Indexed | Flagged | KEV | Size | Build time |
  |---|---|---|---|---|---|---|---|---|---|
  | 1,517 | 1,475 | 42 | 0 | 222 | 1,253 | 4 | 11 | 8.1 MB | 1 min 35 s |

- Merged `phase1-data-ingest` into `main`. 58 tests pass on the merged result.

**What I learned**
- Test data needs to *cover the features*, not just be a random sample. A snapshot that looks realistic can still have zero examples of the thing you want to test. Picking a few packages deliberately fixed it.
- Only 41 PyPI advisories in the whole live database are linked to a KEV entry. "Actively exploited" is rare for Python packages, which makes it a strong urgency signal when it does appear.
- Answer to Day 4's open question: no, 1 KEV entry was not enough; the snapshot now includes KEV-listed packages on purpose.

**Open questions**
- Should I put the repo on GitHub now and switch to one pull request per phase, or wait until the scanner works?

**Later the same day: Phase 2 (scanner) built, reviewed, fixed** (branch `phase2-scanner`)
- Wrote the Phase 2 plan and built the scanner test-first: requirements parser, version matching, reading one package from SQLite, grouping duplicate advisories into findings, CLI, and the `scan_cases` exam. Decisions D15 to D19.
- A final review of the whole branch found 5 real defects (see Challenges); a fix wave followed, decisions D20 to D22. Tests went from 101 to 123, exam from 25 to 26 cases.

**Next**
- Finish Phase 2: write docs, record real numbers, merge.

### Day 4 — 2026-09-28: Phase 1 built (data ingest)
**What I did**
- Built all of Phase 1, test-first: settings, OSV parser, KEV parser, injection scanner, SQLite store, Chroma index, build pipeline with atomic swap, CLI, frozen snapshot, and the LLM interface (`ollama` / `github` / `fake`). 56 unit tests, no network calls.
- First real live build (numbers from `data/live/manifest.json`):

  | Advisories stored | Withdrawn (skipped) | Malformed | Malware (`MAL-`) | Indexed in Chroma | Flagged by injection scanner | KEV entries | Build time |
  |---|---|---|---|---|---|---|---|
  | 25,164 | 578 | 0 | 11,760 | 13,404 | 15 | 1,728 | 20 min 2 s |

- Frozen snapshot for CI: 1,303 raw advisory files, 6.2 MB (under the 10 MB limit), 1 KEV entry. Frozen build: 1,264 advisories (1,303 − 39 withdrawn), 0 malformed, 221 malware, 1,043 indexed; 1 min 17 s.
- Checked by hand: `CVE-2023-30861` (Flask session cookie leak) → flask, fixed in 2.2.5 and 2.3.2. Correct.
- Smoke-tested the local model through my own `complete()` function: asked for JSON, got `{"ok": true}`.

**What I learned**
- The injection scanner flagged 15 advisories: 10 "ignore instructions", 4 "system prompt", 1 chat-markup. **All 15 are real advisories about AI tools** (Open WebUI, PraisonAI, Langroid, mcp-atlassian) whose text *quotes* attack examples. So the answer to Day 3's open question is: yes, it does flag real advisories about prompt injection. That's an acceptable trade-off: they stay in the database and are only hidden from the LLM (Phase 5).
- The full build took 20 minutes, twice my estimate, and made the laptop hot: embedding 13,404 documents keeps all CPU cores busy (403% CPU). That's fine for a nightly job, but it's a reason to keep CI on the small frozen snapshot.
- Mock objects can behave differently from real ones (see Challenges).

**Open questions**
- Only 1 KEV entry matches the snapshot packages. Is that enough to test the "actively exploited" signal in exams, or should the snapshot deliberately include a KEV-listed Python package?

**Next**
- Phase 2: the scanner (read `requirements.txt`, compare versions against affected ranges).

### Day 3 — 2026-09-27: Spec approved, Phase 1 plan written
**What I did**
- Approved the design spec.
- Looked at the real data before planning: OSV PyPI export = 25,742 advisories (34 MB zip; 6,338 GHSA, 7,611 PYSEC, 11,785 MAL, 8 OSV); 578 withdrawn; CISA KEV feed downloads fine.
- Wrote the Phase 1 build plan (11 test-first tasks): `docs/superpowers/plans/2026-09-27-phase1-data-ingest.md`.
- Made decisions D11–D13.

**What I learned**
- Almost half of the "vulnerabilities" for Python are actually malware packages (typosquats like `ascii2text` pretending to be `art`).
- Checking library behaviour *before* writing the plan catches bugs early (see Challenges).
- Embedding is the slow step: ~9 s per 200 long documents on my Mac, so the full build takes ~10 minutes.

**Open questions**
- Will the injection scanner wrongly flag real advisories *about* prompt injection (e.g. in LangChain)? Check the flagged list after the first real build.

**Next**
- Build Phase 1, task by task (native approach), starting with Task 1.

### Day 2 — 2026-09-26: Written design spec
**What I did**
- Turned yesterday's design into a written spec: `docs/superpowers/specs/2026-09-26-cve-copilot-design.md`.
- Pinned down the details: database tables, how version matching works, the three guards, exam sets, pass marks, CI jobs, and 8 build phases.
- Made decisions D8–D10.

**What I learned**
- OSV gives severity as a CVSS *vector* (a coded string), not a number. A small library (`cvss`) turns it into a 0–10 score.
- New data should be built next to the old database and swapped in only when complete. Then a failed download can never leave half-written data.

**Open questions**
- GitHub Models endpoint and model ID: confirm in Phase 6.

**Next**
- Review the spec, write the Phase 1 build plan, and start data ingest.

### Day 1 — 2026-09-25: Idea and design
**What I did**
- Learned what RAG and dynamic RAG are, and how guardrails + CI evals fit together.
- Studied a real failure: the Air Canada chatbot case (2024).
- Chose the topic (CVE copilot) and made decisions D1–D7.
- Designed the architecture (section 3).
- Created the project folder and git repository.

**What I learned**
- Security basics: vulnerability, CVE, patch, affected range, KEV.
- A CI machine without a graphics chip is slow at running AI models, so CI should *call* a hosted model rather than run one.
- Existing tools (Dependabot, pip-audit, OSV-Scanner, Snyk) find problems but don't explain them in a conversation grounded in sources. That gap is what my project fills.

**Open questions**
- Current GitHub Models free limits: check when setting up CI.

**Next**
- Write the design document and step-by-step build plan.
- Phase 1: download and store vulnerability data.

---

## 6. Results dashboard

*Filled in as each phase is built. Numbers come from the exam, never estimated.*

| Metric | Target | Current | Date |
|---|---|---|---|
| Scanner accuracy (scan cases) | 100% | 100% (26/26 cases) | 2026-09-30 |
| Retrieval recall@5 | ≥ 90% | not measured yet | |
| Citation accuracy | ≥ 98% | not measured yet | |
| Groundedness | ≥ 90% | not measured yet | |
| Attack block rate | ≥ 95% | not measured yet | |
| False-block rate | ≤ 5% | not measured yet | |

---

## 7. Likely interview questions

*Answers get sharper as the project grows.*

**Q: Why not just use Dependabot?**
Dependabot tells you *that* something is wrong. My copilot explains what the bug means for your project, how urgent it is (KEV = actively exploited), and how to fix it, with a source for every claim, and you can ask follow-ups.

**Q: How do you stop the AI from making things up?**
Three layers: (1) facts like affected versions come from code, not the AI; (2) the output guard checks every cited ID was actually retrieved and every version number appears in the sources; (3) an AI groundedness check. If the answer fails, it retries once, then falls back to "I couldn't find this."

**Q: How do you know your guardrail works?**
It has its own exam: attack questions (must be blocked) and normal questions that look risky (must *not* be blocked). I track both, because a guard that blocks everything looks perfect on attacks but is useless.

**Q: What makes your RAG "dynamic"?**
It doesn't run the same pipeline for every question. A router picks the route per question, and a grader decides whether the results are good enough, retrying with a rewritten query or admitting it doesn't know.

**Q: How does your CI work if you only use free models?**
The CI machine doesn't run the model. It calls GitHub Models' free tier. Code changes are tested on frozen data, and nightly data updates are tested on frozen code, so every score change has one clear cause.

**Q: What would you do differently / next?**
*(Fill in at the end: see roadmap.)*

---

## 8. Challenges and fixes

*Real problems I hit and how I solved them. Interviewers love these, so log them honestly as they happen.*

| Date | Problem | Cause | Fix | Lesson |
|---|---|---|---|---|
| 2026-09-27 | Rebuilding the Chroma index into the same folder failed: "Collection [advisories] already exists" | Chroma caches one client per folder path; after the folder was renamed and recreated, it still used the old cached one | Call `client.clear_system_cache()` after each build (found while planning, reproduced in a scratch test) | Test how a library behaves on *re-runs*, not just the first run. Nightly jobs re-run forever |
| 2026-09-28 | Retry test crashed: "Cannot call `raise_for_status` as the request instance has not been set" | httpx's `raise_for_status()` needs the original request attached, even on a 200 reply; the test's fake replies had none | Only call `raise_for_status()` when the reply is actually an error (`resp.is_error`) | Fakes in tests can be "thinner" than real objects; write code that only relies on what it needs |
| 2026-09-28 | Injection scanner flagged 15 real advisories | Advisories *about* AI tools quote attack text like "ignore previous instructions" | Kept as a known trade-off: flagged docs are stored, only hidden from the LLM | A security filter always has false positives; measure them and decide consciously |
| 2026-09-29 | Code review found the frozen CI data had 1 KEV entry and 0 flagged advisories | The snapshot picked packages for exam questions plus random extras; KEV and flagged advisories are rare, so none were picked | Added 5 packages chosen by querying the live DB for KEV hits and flagged docs; now 11 KEV, 4 flagged | Check that test data contains examples of every feature you plan to test |
| 2026-09-29 | Final review: `pynetbox==4.0.0` and `torch==2.5.0` showed no advisories although the database has some | Some advisory bounds are not valid versions (`4.1.0-NA`, `2.6.0-NA`); the matcher treated them as "no match", a silent miss | Read the leading number of such a bound (4.1.0); with no number, treat as open-ended. The finding gets a note. Tests for each case; checked on the live database | A scanner must over-report with a label, never skip quietly |
| 2026-09-29 | Final review: `litellm==1.82.7` was not flagged as malware | `MAL-2026-2144` was grouped with `PYSEC-2026-2`; the flag looked only at the main ID | `is_malware` is now computed from every ID and alias in the group; test with a GHSA + MAL pair | After merging records, recompute flags over the whole group |
| 2026-09-29 | Final review: a comment like `# path C:\` swallowed the next line, so `requests==2.19.0` was never checked | A trailing backslash means "line continues", and comment lines were treated the same | Like pip, a comment line is never continued; continued parts are joined with no space. Regression test | Copy the real tool's rules (pip) instead of guessing |
| 2026-09-29 | Final review: the exam could not catch a parser bug | Its expected pins came from our own parser | Pins are hand-written per case; generator fails if the parser disagrees; malware/KEV flags in the key come from raw OSV/KEV files. Added a litellm malware case (26 cases) | An exam whose answers come from the code under test proves nothing |
| 2026-09-29 | Final review: output said "no fix known" or implied a "safe" upgrade when it was not | One advisory can stay unfixed, or a fix for one bug lands in another bug's range | One upgrade per package (fewest advisories still hitting it, finals first), with "still affected by: ..." listed; "no fixed version known" only when there is none | Wording in a security tool is a claim; make it true |

---

## 9. Roadmap / future improvements
- Support more languages (`package.json` for JavaScript, `go.mod` for Go).
- Move the pipeline to LangGraph for visual tracing.
- Compare retrieval methods (keyword vs meaning vs hybrid) and publish the results.
- Turn production failures into new exam questions automatically.
