"""Write evals/data/scan_cases.jsonl. Run once by hand, review the diff, commit.

The expected findings come from the OSV.dev API, which does its own version
matching, so the exam checks our scanner against an independent answer key (D19).
Only IDs present and not withdrawn in the frozen snapshot are kept, so the key
matches the frozen data even if OSV adds advisories later. The pins sent to OSV
are hand-written (not taken from our parser), and the malware/KEV flags come
from the raw snapshot files, never from the scanner.

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
KEV_FILE = PROJECT_ROOT / "data" / "frozen" / "raw" / "kev.json"
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

# (case id, requirements text, expected pins (canonical name, version),
#  expected "not pinned" line numbers, expected "skipped" line numbers)
CASES = [
    ("flask-2.2.0", "flask==2.2.0\n", [("flask", "2.2.0")], [], []),
    ("flask-2.3.1", "flask==2.3.1\n", [("flask", "2.3.1")], [], []),
    ("flask-3.1.2", "flask==3.1.2\n", [("flask", "3.1.2")], [], []),
    ("django-3.2.0", "django==3.2.0\n", [("django", "3.2.0")], [], []),
    ("django-4.2.16", "Django==4.2.16\n", [("django", "4.2.16")], [], []),
    ("django-prerelease", "django==4.2rc1\n", [("django", "4.2rc1")], [], []),
    ("werkzeug-2.2.2", "werkzeug==2.2.2\n", [("werkzeug", "2.2.2")], [], []),
    ("jinja2-2.10", "Jinja2==2.10\n", [("jinja2", "2.10")], [], []),
    ("requests-2.19.0", "requests==2.19.0\n", [("requests", "2.19.0")], [], []),
    ("urllib3-1.26.4", "urllib3==1.26.4\n", [("urllib3", "1.26.4")], [], []),
    ("pyyaml-5.3", "PyYAML==5.3\n", [("pyyaml", "5.3")], [], []),
    ("pillow-10.0.0-kev", "Pillow==10.0.0\n", [("pillow", "10.0.0")], [], []),
    ("cryptography-3.3.2", "cryptography==3.3.2\n", [("cryptography", "3.3.2")], [], []),
    ("aiohttp-3.8.1", "aiohttp==3.8.1\n", [("aiohttp", "3.8.1")], [], []),
    ("sqlalchemy-1.2.0", "SQLAlchemy==1.2.0\n", [("sqlalchemy", "1.2.0")], [], []),
    ("paramiko-2.4.0", "paramiko==2.4.0\n", [("paramiko", "2.4.0")], [], []),
    ("lxml-4.6.2", "lxml==4.6.2\n", [("lxml", "4.6.2")], [], []),
    ("setuptools-65.5.0", "setuptools==65.5.0\n", [("setuptools", "65.5.0")], [], []),
    ("gunicorn-20.0.4", "gunicorn==20.0.4\n", [("gunicorn", "20.0.4")], [], []),
    ("starlette-0.27.0", "starlette==0.27.0\n", [("starlette", "0.27.0")], [], []),
    ("litellm-1.40.0", "litellm==1.40.0\n", [("litellm", "1.40.0")], [], []),
    ("litellm-1.82.7-malware", "litellm==1.82.7\n", [("litellm", "1.82.7")], [], []),
    ("langflow-1.0.0", "langflow==1.0.0\n", [("langflow", "1.0.0")], [], []),
    ("unknown-package", "definitely-not-a-real-package-cvecopilot==1.0\n",
     [("definitely-not-a-real-package-cvecopilot", "1.0")], [], []),
    ("windows-bom-crlf", "\ufeffjinja2==2.10\r\nwerkzeug==2.2.2\r\n",
     [("jinja2", "2.10"), ("werkzeug", "2.2.2")], [], []),
    ("mixed-file", MIXED, [("flask", "2.2.0"), ("requests", "2.19.0"), ("pyyaml", "5.3")],
     [5, 7], [2, 6, 13]),
]


def check_parse(case_id: str, text: str, pins, not_pinned, skipped) -> None:
    """Stop if our parser disagrees with the hand-written answer for this file."""
    parsed = parse_requirements(text)
    got = {"pins": [(p.name, p.version) for p in parsed.pins],
           "not_pinned": [n.line_no for n in parsed.not_pinned],
           "skipped": [n.line_no for n in parsed.skipped]}
    want = {"pins": [tuple(p) for p in pins], "not_pinned": not_pinned, "skipped": skipped}
    for key in got:
        if got[key] != want[key]:
            sys.exit(f"{case_id}: parser gives {key}={got[key]}, hand-written answer is {want[key]}")


def expected_flags(records: dict[str, list[str]], osv_dir: Path, kev_cves: set[str]) -> dict:
    """Per package: malware = any MAL- ID; kev = any ID or alias (from the raw file) in KEV."""
    flags = {}
    for pkg, ids in records.items():
        names = set(ids)
        for i in ids:
            names.update(json.loads((osv_dir / f"{i}.json").read_bytes()).get("aliases", []))
        flags[pkg] = {"malware": any(i.startswith("MAL-") for i in ids), "kev": bool(names & kev_cves)}
    return flags


def _snapshot_ids() -> set[str]:
    return {p.stem for p in SNAPSHOT.glob("*.json")
            if not json.loads(p.read_bytes()).get("withdrawn")}


def _query_osv(pins: list[tuple[str, str]]) -> list[list[str]]:
    body = {"queries": [{"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
                        for name, version in pins]}
    resp = httpx.post(OSV_QUERYBATCH, json=body, timeout=60)
    resp.raise_for_status()
    results = resp.json()["results"]
    if any("next_page_token" in r for r in results):
        sys.exit("OSV returned a paged result; this generator does not handle paging")
    return [sorted(v["id"] for v in r.get("vulns", [])) for r in results]


def main() -> int:
    known = _snapshot_ids()
    kev_cves = {v["cveID"] for v in json.loads(KEV_FILE.read_bytes())["vulnerabilities"]}
    for case_id, text, pins, not_pinned, skipped in CASES:
        check_parse(case_id, text, pins, not_pinned, skipped)
    all_pins = [tuple(p) for _, _, pins, _, _ in CASES for p in pins]
    answers = dict(zip(all_pins, _query_osv(all_pins)))      # one network call for every case
    rows = []
    for case_id, text, pins, not_pinned, skipped in CASES:
        records, not_in_snapshot = {}, []
        for pin in pins:
            osv_ids = answers[tuple(pin)]
            not_in_snapshot += [i for i in osv_ids if i not in known]
            if in_snap := [i for i in osv_ids if i in known]:
                records.setdefault(pin[0], []).extend(in_snap)
        rows.append({"id": case_id, "requirements": text,
                     "expected": {"records": records,
                                  "flags": expected_flags(records, SNAPSHOT, kev_cves),
                                  "not_pinned": not_pinned, "skipped": skipped},
                     "source": f"api.osv.dev {date.today().isoformat()}",
                     "not_in_snapshot": not_in_snapshot})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"Wrote {len(rows)} cases to {OUT}; "
          f"{sum(len(r['not_in_snapshot']) for r in rows)} OSV IDs not in the snapshot were left out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
