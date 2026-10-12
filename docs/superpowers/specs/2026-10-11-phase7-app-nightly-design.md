# Phase 7: App, nightly data, live recall — Design

**Date:** 2026-10-11
**Status:** Built 2026-10-11 on branch `phase7-app`. Decisions D49–D51 in `docs/PROJECT_LOG.md`.
**Parent spec:** `2026-09-26-cve-copilot-design.md` sections 5.6, 6 and 10.

---

## 1. Goal

Make the project usable and keep its data fresh:

1. A Streamlit app: scan a `requirements.txt`, then chat about the results.
2. A nightly CI job: fresh OSV + KEV data, exams with the code on `main`, then publish the data
   (pass) or open an issue (fail).
3. `--pull-release`: the app's data comes from the last night that passed.
4. Close the live retrieval gap first: the nightly job runs the retrieval exam on live data, and
   live recall@5 was 87.9%, below the 90% pass mark.

## 2. Live recall gap (D49)

The four live misses had three different causes (measured 2026-10-11 on the 2026-09-28 live data):

| Item | Cause | Fix |
|---|---|---|
| `c-werkzeug-entropy` ("debugger PIN generated with too little randomness") | The right advisory ranks 1st once it is a candidate, but meaning search alone never put it in the 20-document pool | Keyword candidates: SQLite FTS5 (BM25) top 10 join the meaning pool, then the existing hybrid re-rank (D28) orders them |
| `h-mlflow-traversal` ("Is there a path traversal bug in mlflow?") | Answer key: accepted 1 advisory; live data has 21 mlflow path-traversal advisories and every one answers the question | Key lists all 21 as alternatives (rule: an mlflow advisory whose summary says "traversal") |
| `h-binwalk-symlink` ("firmware extraction tool …") | Needs world knowledge: the advisory never says "firmware" | None; documented miss |
| `h-ecdsa-signature` ("… in an ECDSA library …") | `ecdsa` is a package in live data, so the router picks the package route; the bug is in `starkbank-ecdsa` | None; documented miss (a router change for one question would be tuning on the exam) |

**Rejected:** cross-encoder re-rankers from fastembed (MiniLM-L-6/L-12: live stays 87.9% and a
frozen item breaks; jina-turbo: frozen 100%, live 84.8%). More keyword candidates (20 or 40)
pushed live back to 87.9%: noise crowds the pool.

## 3. App (`src/cve_copilot/app.py`, helpers in `ui.py`)

- **Sidebar:** which data (live if built or pulled, else frozen), its build date and counts,
  the model, and a warning with the fix command when Ollama or the model is missing. Buttons:
  *Reload data* (clears the cached Chroma client after a pull swapped the folder) and *Clear chat*.
- **Scan tab:** upload or paste, or *Try an example*. Metrics, a findings table with OSV links,
  CVSS, KEV/MALWARE flag and fix version, suggested upgrades, and the lines not checked.
- **Chat tab:** `pipeline.answer` with the scan as context. Each reply shows its sources (OSV
  links, packages, CVSS, KEV) and a trace. A model that cannot be reached gives a message, not a crash.
- `ui.py` has no Streamlit code, so it is unit-tested; the page is tested headless with
  Streamlit's `AppTest` (answer loop stubbed: it has its own tests).
- Usage statistics off (`.streamlit/config.toml`).

## 4. Release asset (D50)

- `--pack-release DIR`: `data/live` → `DIR/cve-data.tar.gz` + `cve-data.tar.gz.sha256`.
- `--pull-release`: download both from the `data-latest` release of `CVE_RELEASE_REPO`
  (default `divyabasavraj/cve-copilot`), check the SHA-256, extract with tarfile's `data`
  filter (no paths outside the folder, no links out), check `cve.db`, `chroma/` and
  `manifest.json` are there, then swap into `data/live` the same way a build does.
  Any failure keeps the old data and exits 1.

## 5. Nightly CI (`.github/workflows/nightly.yml`, D50)

- 02:17 UTC daily, plus manual runs. Timeout 90 minutes.
- Steps: `ingest --target live` → Ollama (shared `.github/actions/setup-ollama`) →
  `evals.run --target live --exams retrieval,answers,guards --sample`.
- **Pass:** pack and upload to release `data-latest` (archive first, checksum second, so an
  app pulling in between gets a checksum error and keeps its old data).
- **Fail:** one issue per failure kind (label `nightly`): "a score missed its pass mark"
  (exit 1) or "infrastructure error" (anything else). A repeat failure comments on the open issue.
- The scan exam is not run nightly: its answer key comes from the frozen raw files, so new
  advisories would fail it with no bug. It runs on every push.

## 6. Testing

- Unit: FTS table contents, keyword candidates (BM25 order, stopwords, old DB without the
  table), keyword docs reaching the re-rank; release round trip, bad checksum, path escape,
  missing files, CLI pull/pack/failure; UI helpers; four headless app tests.
- Exams: retrieval on frozen and live (results in the log, D49).
- Nightly: schedules only run from `main`, so the first real run happens after the merge.
