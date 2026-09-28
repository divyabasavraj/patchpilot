"""Pick a small, fixed set of raw files for PR CI (spec 5.1 'Frozen snapshot')."""
import json
import random
import shutil
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path

from packaging.utils import canonicalize_name

from ..config import Settings
from .sources import KEV_URL, OSV_URL, download, iter_osv_files


def _packages(rec: dict) -> set[str]:
    return {canonicalize_name(a["package"]["name"]) for a in rec.get("affected", [])
            if a.get("package", {}).get("ecosystem") == "PyPI" and a["package"].get("name")}


def select_snapshot(files: Iterable[tuple[str, bytes]], packages: set[str],
                    n_distractors: int, seed: int = 42) -> list[tuple[str, bytes]]:
    keep, others = [], []
    for name, raw in files:
        try:
            rec = json.loads(raw)
            pkgs = _packages(rec)
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
        (keep if pkgs & packages else others).append((name, raw))
    others.sort()
    keep += random.Random(seed).sample(others, min(n_distractors, len(others)))
    return sorted(keep)


def filter_kev(kev_data: dict, cve_ids: set[str]) -> dict:
    out = dict(kev_data)
    out["vulnerabilities"] = [v for v in kev_data["vulnerabilities"] if v.get("cveID") in cve_ids]
    return out


def main() -> int:
    frozen = Settings.from_env().data_dir / "frozen"
    packages = {canonicalize_name(line.strip()) for line in (frozen / "packages.txt").read_text().splitlines()
                if line.strip() and not line.startswith("#")}
    with tempfile.TemporaryDirectory() as tmp:
        osv_zip, kev_file = Path(tmp) / "osv.zip", Path(tmp) / "kev.json"
        download(OSV_URL, osv_zip)
        download(KEV_URL, kev_file)
        chosen = select_snapshot(iter_osv_files(osv_zip), packages, n_distractors=500)
        ids = set()
        for _, raw in chosen:
            rec = json.loads(raw)
            ids |= {rec["id"], *rec.get("aliases", [])}
        kev = filter_kev(json.loads(kev_file.read_bytes()), ids)

    raw_dir = frozen / "raw"
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    (raw_dir / "osv").mkdir(parents=True)
    for name, raw in chosen:
        (raw_dir / "osv" / Path(name).name).write_bytes(raw)
    (raw_dir / "kev.json").write_text(json.dumps(kev, indent=1))
    print(f"Wrote {len(chosen)} advisories and {len(kev['vulnerabilities'])} KEV entries to {raw_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
