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

---

## 5. Daily journal

*Newest entry first. One entry per work day.*

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
| Scanner accuracy (scan cases) | 100% | not measured yet | |
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
| | | | | |

---

## 9. Roadmap / future improvements
- Support more languages (`package.json` for JavaScript, `go.mod` for Go).
- Move the pipeline to LangGraph for visual tracing.
- Compare retrieval methods (keyword vs meaning vs hybrid) and publish the results.
- Turn production failures into new exam questions automatically.
