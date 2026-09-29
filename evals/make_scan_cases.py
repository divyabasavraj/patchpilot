"""Write evals/data/scan_cases.jsonl. Run once by hand, review the diff, commit.

The expected findings come from the OSV.dev API, which does its own version
matching, so the exam checks our scanner against an independent answer key (D19).
Only IDs present and not withdrawn in the frozen snapshot are kept, so the key
matches the frozen data even if OSV adds advisories later.

    uv run python -m evals.make_scan_cases
"""
import json
import sys
from datetime import date
from pathlib import Path

import httpx

from cve_copilot.config import PROJECT_ROOT
from cve_copilot.scanner import parse_requirements

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
SNAPSHOT = PROJECT_ROOT / "data" / "frozen" / "raw" / "osv"
OUT = Path(__file__).parent / "data" / "scan_cases.jsonl"

MIXED = ("# app requirements\n"                                      # 1
         "-r base.txt\n"                                             # 2 skipped
         "Flask==2.2.0  # web framework\n"                           # 3
         "requests[socks]==2.19.0 ; python_version >= '3.8'\n"       # 4
         "django>=4.2\n"                                             # 5 not pinned
         "-e git+https://github.com/pallets/click.git#egg=click\n"   # 6 skipped
         "urllib3\n"                                                 # 7 not pinned
         "\n"                                                        # 8
         "PyYAML==5.3 \\\n"                                          # 9
         "    --hash=sha256:aaaa \\\n"                               # 10
         "    --hash=sha256:bbbb\n"                                  # 11
         "    # via -r requirements.in\n"                            # 12
         "git+https://github.com/psf/black.git\n")                   # 13 skipped

# (case id, requirements text, expected "not pinned" line numbers, expected "skipped" line numbers)
CASES = [
    ("flask-2.2.0", "flask==2.2.0\n", [], []),
    ("flask-2.3.1", "flask==2.3.1\n", [], []),
    ("flask-3.1.2", "flask==3.1.2\n", [], []),
    ("django-3.2.0", "django==3.2.0\n", [], []),
    ("django-4.2.16", "Django==4.2.16\n", [], []),
    ("django-prerelease", "django==4.2rc1\n", [], []),
    ("werkzeug-2.2.2", "werkzeug==2.2.2\n", [], []),
    ("jinja2-2.10", "Jinja2==2.10\n", [], []),
    ("requests-2.19.0", "requests==2.19.0\n", [], []),
    ("urllib3-1.26.4", "urllib3==1.26.4\n", [], []),
    ("pyyaml-5.3", "PyYAML==5.3\n", [], []),
    ("pillow-10.0.0-kev", "Pillow==10.0.0\n", [], []),
    ("cryptography-3.3.2", "cryptography==3.3.2\n", [], []),
    ("aiohttp-3.8.1", "aiohttp==3.8.1\n", [], []),
    ("sqlalchemy-1.2.0", "SQLAlchemy==1.2.0\n", [], []),
    ("paramiko-2.4.0", "paramiko==2.4.0\n", [], []),
    ("lxml-4.6.2", "lxml==4.6.2\n", [], []),
    ("setuptools-65.5.0", "setuptools==65.5.0\n", [], []),
    ("gunicorn-20.0.4", "gunicorn==20.0.4\n", [], []),
    ("starlette-0.27.0", "starlette==0.27.0\n", [], []),
    ("litellm-1.40.0", "litellm==1.40.0\n", [], []),
    ("langflow-1.0.0", "langflow==1.0.0\n", [], []),
    ("unknown-package", "definitely-not-a-real-package-cvecopilot==1.0\n", [], []),
    ("windows-bom-crlf", "﻿jinja2==2.10\r\nwerkzeug==2.2.2\r\n", [], []),
    ("mixed-file", MIXED, [5, 7], [2, 6, 13]),
]


def _snapshot_ids() -> set[str]:
    return {p.stem for p in SNAPSHOT.glob("*.json")
            if not json.loads(p.read_bytes()).get("withdrawn")}


def _query_osv(pins) -> list[list[str]]:
    body = {"queries": [{"package": {"name": p.name, "ecosystem": "PyPI"}, "version": p.version}
                        for p in pins]}
    resp = httpx.post(OSV_QUERYBATCH, json=body, timeout=60)
    resp.raise_for_status()
    results = resp.json()["results"]
    if any("next_page_token" in r for r in results):
        sys.exit("OSV returned a paged result; this generator does not handle paging")
    return [sorted(v["id"] for v in r.get("vulns", [])) for r in results]


def main() -> int:
    known = _snapshot_ids()
    rows = []
    for case_id, text, not_pinned, skipped in CASES:
        parsed = parse_requirements(text)
        got_np = [n.line_no for n in parsed.not_pinned]
        got_sk = [n.line_no for n in parsed.skipped]
        if (got_np, got_sk) != (not_pinned, skipped):
            sys.exit(f"{case_id}: parser gives not_pinned={got_np} skipped={got_sk}, "
                     f"hand-written answer is {not_pinned} / {skipped}")
        records, not_in_snapshot = {}, []
        if parsed.pins:
            for pin, osv_ids in zip(parsed.pins, _query_osv(parsed.pins)):
                in_snap = [i for i in osv_ids if i in known]
                not_in_snapshot += [i for i in osv_ids if i not in known]
                if in_snap:
                    records.setdefault(pin.name, []).extend(in_snap)
        rows.append({"id": case_id, "requirements": text,
                     "expected": {"records": records, "not_pinned": not_pinned, "skipped": skipped},
                     "source": f"api.osv.dev {date.today().isoformat()}",
                     "not_in_snapshot": not_in_snapshot})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"Wrote {len(rows)} cases to {OUT}; "
          f"{sum(len(r['not_in_snapshot']) for r in rows)} OSV IDs not in the snapshot were left out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
