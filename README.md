# CVE Copilot

A chat assistant for Python security advisories. Ask about a CVE or a package, or upload a
`requirements.txt`, and get a cited answer. Facts such as affected versions come from code;
the AI only explains them, and three guards check the question, the sources and the answer.
Built with free tools only: Ollama (`qwen2.5:7b`), OSV.dev, CISA KEV, SQLite, Chroma.

## Exams and CI

Run every exam against the pass marks in `evals/thresholds.toml`:

    uv run python -m cve_copilot.ingest --target frozen   # once
    uv run python -m evals.run                            # all four exams, full data
    uv run python -m evals.run --exams retrieval,answers,guards --sample   # what CI runs

Exit code 0 = passed, 1 = a score missed its pass mark, 2 = something broke (Ollama, DB).
The report is written to `evals/report.md`.

CI (`.github/workflows/pr.yml`): every push runs the unit tests and the scan exam. Add the
`ai-exams` label to a PR (or start the workflow by hand) to also run the retrieval exam and a
fixed sample of the answers and guards exams with `qwen2.5:7b` on the runner.
