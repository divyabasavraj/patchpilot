"""CLI: uv run python -m cve_copilot.scanner requirements.txt [--target live|frozen]"""
import argparse
import sys
from pathlib import Path

from ..config import Settings
from .models import ScanReport, Upgrade
from .scan import scan


def _upgrade_text(up: Upgrade) -> str:
    if up.version is None:
        return ": no fixed version known"
    if up.still_affected:
        return f" -> {up.version} (still affected by: {', '.join(up.still_affected)} \u2014 no fix known)"
    return f" -> {up.version}"


def format_report(report: ScanReport) -> str:
    lines = [f"Checked {len(report.checked)} pinned packages: "
             f"{len(report.findings)} findings in {len(report.upgrades)} packages."]
    if report.findings:
        lines += ["", f"{'PACKAGE':<22} {'VERSION':<12} {'ADVISORY':<22} {'CVSS':>4}  {'FLAG':<7}  FIX"]
        for f in report.findings:
            score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
            flag = "MALWARE" if f.is_malware else ("KEV" if f.in_kev else "")
            lines.append(f"{f.package:<22} {f.version:<12} {f.advisory_id:<22} {score:>4}  "
                         f"{flag:<7}  {f.upgrade_to or 'no fix known'}")
        lines += ["", "Suggested upgrades:"]
        versions = {p.name: p.version for p in report.checked}
        lines += [f"  {pkg} {versions[pkg]}{_upgrade_text(up)}" for pkg, up in report.upgrades.items()]
        notes = [f"{f.package} {f.version}: {n}" for f in report.findings for n in f.notes]
        if notes:
            lines += ["", "Notes:"] + [f"  {n}" for n in notes]
    else:
        lines.append("No known vulnerabilities in the pinned packages.")
    for title, notes in (("Not checked", report.not_pinned), ("Skipped", report.skipped)):
        if notes:
            lines += ["", f"{title}:"]
            lines += [f"  line {n.line_no}: {n.line}  ({n.reason})" for n in notes]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cve_copilot.scanner")
    parser.add_argument("requirements", type=Path)
    parser.add_argument("--target", choices=["live", "frozen"], default="live")
    args = parser.parse_args(argv)
    db_path = Settings.from_env().db_dir(args.target) / "cve.db"
    try:
        text = args.requirements.read_text(encoding="utf-8-sig", errors="replace")
        report = scan(text, db_path)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 2
    print(format_report(report))
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
