"""Run any set of exams, compare each score with its pass mark, write a report (D44, D47).

    uv run python -m evals.run [--exams scan,retrieval,answers,guards] [--sample]
                               [--target frozen|live] [--out DIR]

--sample runs the answers and guards exams on the fixed CI sample (evals/data/ci_sample.toml);
scan and retrieval always run in full. Writes DIR/report.json and DIR/report.md (DIR defaults
to evals/) and appends the table to $GITHUB_STEP_SUMMARY when that is set.

Exit codes: 0 every metric passed; 1 a score missed its pass mark (the code got worse);
2 something broke (Ollama down, model missing, DB not built, bad sample): fix CI, not code.
"""
import argparse
import json
import os
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path

from cve_copilot.config import Settings
from evals import answers_exam, guards_exam, retrieval_exam, scan_exam, thresholds

EXAMS = ("scan", "retrieval", "answers", "guards")
SAMPLE = Path(__file__).parent / "data" / "ci_sample.toml"
REPORT_DIR = Path(__file__).parent
# Each list in the sample file picks IDs from this exam data file.
SAMPLE_FILES = {"answers": answers_exam.CASES, "attacks": guards_exam.ATTACKS,
                "benign": guards_exam.BENIGN}
BUILD_HINT = "build it first: uv run python -m cve_copilot.ingest --target frozen (or live)"

Runner = Callable[[str, Path, dict | None, Path], dict]


class SampleError(ValueError):
    """The CI sample file is malformed or names an ID that is not in the exam data."""


def _ids(path: Path) -> list[str]:
    return [json.loads(line)["id"] for line in path.read_text().splitlines() if line.strip()]


def load_sample(path: Path = SAMPLE, files: dict[str, Path] = SAMPLE_FILES) -> dict[str, list[str]]:
    with path.open("rb") as f:
        sample = tomllib.load(f)
    if set(sample) != set(files):
        raise SampleError(f"{path.name} must list exactly: {', '.join(sorted(files))}")
    for name, ids in sample.items():
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise SampleError(f"{path.name}: {name} must be a list of ID strings")
        unknown = sorted(set(ids) - set(_ids(files[name])))
        if unknown:
            raise SampleError(f"{path.name}: {name} has IDs not in {files[name].name}: "
                              f"{', '.join(unknown)}")
    return sample


def subset(path: Path, ids: list[str], out: Path) -> Path:
    """Copy only the cases whose ID is in ids, keeping the file's order."""
    keep = set(ids)
    lines = [line for line in path.read_text().splitlines()
             if line.strip() and json.loads(line)["id"] in keep]
    out.write_text("".join(line + "\n" for line in lines))
    return out


def run_exam(name: str, db_dir: Path, sample: dict | None, tmp: Path) -> dict:
    def pick(key: str, path: Path) -> Path:
        return subset(path, sample[key], tmp / f"{key}.jsonl") if sample else path

    if name == "scan":
        return scan_exam.run(scan_exam.CASES, db_dir / "cve.db")
    if name == "retrieval":
        return retrieval_exam.run(retrieval_exam.CASES, db_dir)
    if name == "answers":
        return answers_exam.run(pick("answers", answers_exam.CASES), db_dir)
    if name == "guards":
        return guards_exam.run(pick("attacks", guards_exam.ATTACKS),
                               pick("benign", guards_exam.BENIGN), db_dir)
    raise ValueError(f"unknown exam {name!r}")


def _report(sample: bool) -> dict:
    return {"sample": sample, "exams": {}, "error": None}


def run(exams, db_dir: Path, *, sample: dict | None = None, runner: Runner = run_exam) -> dict:
    report = _report(sample is not None)
    # Checked first: sqlite3 would otherwise create an empty cve.db and fail later.
    if not (db_dir / "cve.db").exists():
        report["error"] = {"exam": None, "message": f"No database in {db_dir}; {BUILD_HINT}"}
        return report
    with tempfile.TemporaryDirectory() as tmp:
        for name in exams:
            try:
                result = runner(name, db_dir, sample, Path(tmp))
                misses = thresholds.check(name, result)
            except Exception as e:   # any crash is an infrastructure error (exit 2)
                report["error"] = {"exam": name, "message": f"{type(e).__name__}: {e}"}
                break
            report["exams"][name] = {"result": result,
                                     "misses": [m._asdict() for m in misses]}
    return report


def exit_code(report: dict) -> int:
    if report["error"]:
        return 2
    return 1 if any(e["misses"] for e in report["exams"].values()) else 0


def _items(name: str, result: dict) -> str:
    if name == "guards":
        return f"{len(result['attacks'])} attacks, {len(result['benign'])} benign"
    return str(result["cases"] if name == "scan" else result["items"])


def to_markdown(report: dict) -> str:
    kind = "CI sample" if report["sample"] else "full"
    lines = [f"## CVE Copilot exams ({kind})", "",
             "| Exam | Metric | Score | Pass mark | Items | |", "|---|---|---|---|---|---|"]
    for name, exam in report["exams"].items():
        missed = {m["metric"] for m in exam["misses"]}
        for metric, mark, upper in thresholds.marks(name):
            lines.append(f"| {name} | {metric} | {exam['result'][metric]:.1%} | "
                         f"{'≤' if upper else '≥'} {mark:.1%} | {_items(name, exam['result'])} | "
                         f"{'❌' if metric in missed else '✅'} |")
    lines.append("")
    code = exit_code(report)
    if code == 2:
        err = report["error"]
        where = f" in {err['exam']}" if err["exam"] else ""
        lines.append(f"**ERROR{where}:** {err['message']} (infrastructure problem, exit 2)")
    elif code == 1:
        n = sum(len(e["misses"]) for e in report["exams"].values())
        lines.append(f"**FAIL:** {n} metric(s) missed the pass mark (exit 1)")
    else:
        lines.append("**PASS:** every metric met its pass mark (exit 0)")
    return "\n".join(lines) + "\n"


def write(report: dict, out_dir: Path) -> str:
    md = to_markdown(report)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, default=str))
    (out_dir / "report.md").write_text(md)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(md)
    return md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.run")
    parser.add_argument("--exams", default=",".join(EXAMS),
                        help=f"comma-separated, from: {','.join(EXAMS)}")
    parser.add_argument("--sample", action="store_true",
                        help="answers and guards on the fixed CI sample only")
    parser.add_argument("--target", choices=["live", "frozen"], default="frozen")
    parser.add_argument("--out", type=Path, default=REPORT_DIR,
                        help="folder for report.json and report.md")
    args = parser.parse_args(argv)
    exams = [e.strip() for e in args.exams.split(",") if e.strip()]
    unknown = [e for e in exams if e not in EXAMS]
    if unknown or not exams:
        parser.error(f"unknown exam(s): {', '.join(unknown) or '(none given)'}")
    try:
        sample = load_sample() if args.sample else None
    except (SampleError, OSError, tomllib.TOMLDecodeError) as e:
        report = _report(True)
        report["error"] = {"exam": None, "message": f"{type(e).__name__}: {e}"}
    else:
        report = run(exams, Settings.from_env().db_dir(args.target), sample=sample)
    print(write(report, args.out))
    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
