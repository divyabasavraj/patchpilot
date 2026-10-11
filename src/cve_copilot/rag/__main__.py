"""CLI: uv run python -m cve_copilot.rag "question" [--target live|frozen] [-k 5]
       [--answer] [--requirements FILE]

Without --answer it shows the route and the retrieved documents; with --answer it runs the
whole loop (grade, retry once, generate) and prints the answer, its sources and the trace.
"""
import argparse
import sys
from pathlib import Path

from ..config import Settings
from ..embeddings import embed
from ..scanner import scan
from ..scanner.requirements import decode_requirements
from . import search
from .models import Doc, Route
from .pipeline import Answer, answer
from .retriever import EmbedFn


def format_result(route: Route, docs: list[Doc]) -> str:
    extra = "".join(f" {name}={','.join(vals)}" for name, vals in
                    (("ids", route.ids), ("packages", route.packages)) if vals)
    lines = [f"Route: {route.kind} ({route.by}){extra}"]
    if not docs:
        lines.append("No documents." if route.kind != "chat" else "No search needed.")
    for d in docs:
        cvss = f"{d.cvss_score:.1f}" if d.cvss_score is not None else "-"
        score = f"{d.score:.2f}" if d.score is not None else "-"
        flags = " ".join(f for f, on in (("KEV", d.in_kev), ("FLAGGED", d.flagged)) if on)
        lines.append(f"  {d.id:<22} {cvss:>4}  {score:>5}  {flags:<11} {d.summary[:70]}")
    return "\n".join(lines)


def format_trace(t) -> str:
    if t.route is None:
        return f"input guard={t.input_label} ({t.input_by}), outcome={t.outcome}"
    trace = f"route={t.route.kind} ({t.route.by}), retrieved={len(t.retrieved)}, " \
            f"relevant={len(t.graded)}, outcome={t.outcome}"
    if t.dropped:
        trace += f", dropped={','.join(f'{i} ({why})' for i, why in t.dropped)}"
    if len(t.output_issues) > 1:
        trace += f", regenerated after: {'; '.join(t.output_issues[0])}"
    if t.rewritten_query:
        trace += f", rewritten query={t.rewritten_query!r}"
    if t.grader_error:
        trace += f", grader error={t.grader_error}"
    return trace


def format_answer(result: Answer) -> str:
    lines = [result.text, ""]
    if result.sources:
        lines.append("Sources:")
        lines += [f"  {d.id:<22} {d.summary[:70]}" for d in result.sources]
    lines.append(f"Trace: {format_trace(result.trace)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None, *, embed_fn: EmbedFn = embed) -> int:
    parser = argparse.ArgumentParser(prog="cve_copilot.rag")
    parser.add_argument("question")
    parser.add_argument("--target", choices=["live", "frozen"], default="live")
    parser.add_argument("-k", type=int, default=5)
    parser.add_argument("--answer", action="store_true", help="generate a cited answer")
    parser.add_argument("--requirements", type=Path, help="scan this file and use it as facts")
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    db_dir = settings.db_dir(args.target)
    try:
        if args.answer or args.requirements:
            report = None
            if args.requirements:
                report = scan(decode_requirements(args.requirements.read_bytes()), db_dir / "cve.db")
            print(format_answer(answer(args.question, db_dir, report=report, k=args.k,
                                       embed_fn=embed_fn, settings=settings)))
        else:
            print(format_result(*search(args.question, db_dir, k=args.k, embed_fn=embed_fn,
                                        settings=settings)))
    except FileNotFoundError as err:
        print(err, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
