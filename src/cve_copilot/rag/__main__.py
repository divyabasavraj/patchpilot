"""CLI: uv run python -m cve_copilot.rag "question" [--target live|frozen] [-k 5]"""
import argparse
import sys

from ..config import Settings
from ..embeddings import embed
from . import search
from .models import Doc, Route
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


def main(argv: list[str] | None = None, *, embed_fn: EmbedFn = embed) -> int:
    parser = argparse.ArgumentParser(prog="cve_copilot.rag")
    parser.add_argument("question")
    parser.add_argument("--target", choices=["live", "frozen"], default="live")
    parser.add_argument("-k", type=int, default=5)
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    try:
        route, docs = search(args.question, settings.db_dir(args.target), k=args.k,
                             embed_fn=embed_fn, settings=settings)
    except FileNotFoundError as err:
        print(err, file=sys.stderr)
        return 2
    print(format_result(route, docs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
