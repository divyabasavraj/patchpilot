# Phase 6 — Evals runner + PR CI: design

*Status: ✅ Done 2026-10-09 (PR #1). Approved in conversation on 2026-10-08. Decisions D44–D48 in `docs/PROJECT_LOG.md`.
This replaces sections 9 ("Pass marks" file name) and 10 (`pr.yml`) of
`2026-09-26-cve-copilot-design.md` where they disagree.*

## 1. Goal

One command runs every exam, compares each score with its pass mark, and writes a
report. GitHub Actions runs the cheap checks on every push and the AI exams on request,
so a pull request shows whether the code got worse.

**Success:** a PR on the public repo shows a green `checks` job, and, when labelled
`ai-exams`, an `ai-exams` job whose summary page has the score table.

**Out of scope (Phase 7):** `nightly.yml`, live-data exams in CI, the Streamlit app.

## 2. Why CI changed from the original spec

The original spec ran every exam on every push with `LLM=github`. GitHub Models was
retired on 2026-07-30 (it now answers every request with a plain "OK"), and a full run
needs about 400 AI calls. So:

- **D44:** cheap exact checks on every push; AI exams on a fixed sample, only on request.
- **D45:** the AI runs with Ollama + `qwen2.5:7b` on the GitHub runner; `LLM=github` is removed.
- **D46:** the repo is public (`divyabasavraj/cve-copilot`), so Actions minutes are free.
- **D47:** pass marks live in one TOML file; the CI sample is a fixed, committed list.

## 3. Components

### 3.1 `evals/thresholds.toml` — the only place pass marks live

```toml
[scan]
accuracy = 1.00

[retrieval]
recall_at_5 = 0.90

[answers]
citation_accuracy = 0.98
groundedness = 0.90

[guards]
block_rate = 0.95
false_block_rate_max = 0.05
```

- A key ending in `_max` is an upper limit (score must be ≤ mark); every other key is a
  lower limit (score must be ≥ mark).
- Read with the standard-library `tomllib` (no new dependency). The spec's
  `thresholds.yaml` becomes `thresholds.toml`.
- A small loader, `evals/thresholds.py`, exposes `load() -> dict` and
  `check(exam, result) -> list[Miss]`, where a `Miss` names the metric, score and mark.
- The four exams drop their own constants (`PASS_MARK`, `PASS_MARKS`, the hard-coded
  `== 1.0` in the scan exam) and call `check()`. Their standalone commands keep working
  and give the same exit codes as today.

### 3.2 `evals/data/ci_sample.toml` — the fixed CI sample

```toml
answers = ["...8 ids..."]
attacks = ["...10 ids, at least 2 of each kind: question, planted, flagged..."]
benign  = ["...8 ids, including bn21..."]
```

- Picked by hand once and committed, so every CI run sits the same test and scores are
  comparable between runs.
- Retrieval and scan always run in full (scan makes no AI calls; retrieval makes few,
  because the router tries its rules before asking the AI).
- The sample uses the **same** pass marks as the full exams. With 8–10 items one miss
  fails; that is intended, since the full frozen run currently scores 100% on these.
- An ID in the sample that is not in the exam data is an error (exit 2), so a renamed
  case can't silently shrink the sample.

### 3.3 `evals/run.py` — one command for every exam

```
uv run python -m evals.run [--exams scan,retrieval,answers,guards] [--sample] [--target frozen|live]
```

- Defaults: all four exams, full data, `--target frozen`.
- Calls each exam's existing `run()` function in-process. With `--sample`, the answers
  and guards cases are filtered to the IDs in `ci_sample.toml` before calling `run()`.
- Writes `evals/report.json` (each exam's summary plus the misses) and
  `evals/report.md` (one table: exam, metric, score, pass mark, ✅/❌, plus item counts
  and whether it was a sample).
- If the `GITHUB_STEP_SUMMARY` environment variable is set, appends `report.md` to that
  file so it shows on the Actions summary page.
- **Exit codes:** `0` every metric passed · `1` at least one metric missed its mark ·
  `2` infrastructure error: any exception while running an exam (Ollama unreachable,
  `LLMUnavailable`, DB missing, bad sample ID). On exit 2 the report still lists which
  exams finished and the error text for the one that crashed.

### 3.4 `.github/workflows/pr.yml`

Triggers: `push`, `pull_request` (including the `labeled` event), `workflow_dispatch`.

| Job | Runs when | Steps |
|---|---|---|
| `checks` | every push and PR | checkout → `astral-sh/setup-uv` → `uv sync` → `uv run pytest` → build frozen DB (`uv run python -m cve_copilot.ingest --target frozen`) → `uv run python -m evals.run --exams scan` |
| `ai-exams` | PR has label `ai-exams`, or `workflow_dispatch`; needs `checks` | same setup + frozen build → install Ollama → restore `~/.ollama/models` from `actions/cache` → `ollama pull qwen2.5:7b` → `uv run python -m evals.run --exams retrieval,answers,guards --sample` with `LLM=ollama` |

- The fastembed model cache is also cached between runs.
- Permissions: `contents: read` only (no secrets are used).
- Both jobs upload `evals/report.json` and `report.md` as build artifacts.
- `ai-exams` has a job timeout (set from the timing test in the first plan task).

### 3.5 Removing `LLM=github`

Delete `src/cve_copilot/llm/github.py`, the `github_*` settings in `config.py`, the
`github` branch in `llm/__init__.py`, and their tests. `LLM` accepts `ollama | fake`.

## 4. Order of work (for the plan)

1. **Timing test first:** create the public repo, push, and run a throwaway workflow
   that installs Ollama, pulls `qwen2.5:7b` and times ~5 pipeline questions. If the
   sampled exams would take too long, switch the CI model to `qwen2.5:3b` (D45 fallback)
   and record the decision. Pick the sample size and job timeout from these numbers.
2. Remove `LLM=github`.
3. `thresholds.toml` + loader; exams switch to it (tests first).
4. `ci_sample.toml` + `run.py` (tests first, with the fake LLM).
5. `pr.yml`; open a test PR with the `ai-exams` label and check both jobs.
6. Docs: spec/plan marked done, log (decisions, metrics from CI, Day entry).

## 5. Testing

- `thresholds`: lower/upper-limit logic, a missing key, a `_max` key.
- `run.py`: a scripted fake-LLM run gives exit 0; a score below its mark gives exit 1;
  an exam that raises gives exit 2 and a report naming the crash; `--sample` filters to
  exactly the listed IDs; an unknown sample ID gives exit 2; the step-summary file gets
  written only when the variable is set.
- Existing exam tests keep passing unchanged (same results, same exit codes).
- CI itself is checked by the test PR in step 5.

## 6. Small tidy-ups done alongside

- Delete the merged `phase5-guards` branch.
- Investigate the tracked 0-byte `data/frozen/cve.db`: if the build always recreates it,
  untrack it and add it to `.gitignore`.
