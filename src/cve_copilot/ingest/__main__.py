"""CLI: uv run python -m cve_copilot.ingest --target live|frozen"""
import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import httpx

from ..config import Settings
from .build import build
from .sources import KEV_URL, OSV_URL, download, iter_osv_files


def main(argv: list[str] | None = None, *, embed_fn=None, downloader=None) -> int:
    parser = argparse.ArgumentParser(prog="cve_copilot.ingest")
    parser.add_argument("--target", choices=["live", "frozen"], default="live")
    args = parser.parse_args(argv)

    if embed_fn is None:
        from ..embeddings import embed as embed_fn
    downloader = downloader or download
    settings = Settings.from_env()
    data_dir = settings.data_dir

    if args.target == "live":
        with tempfile.TemporaryDirectory() as tmp:
            osv_zip, kev_file = Path(tmp) / "osv.zip", Path(tmp) / "kev.json"
            try:
                osv_sha = downloader(OSV_URL, osv_zip)
                kev_sha = downloader(KEV_URL, kev_file)
            except httpx.HTTPError as e:
                print(f"Download failed: {e}. Existing data kept.", file=sys.stderr)
                return 1
            sources = {"osv": {"url": OSV_URL, "sha256": osv_sha},
                       "kev": {"url": KEV_URL, "sha256": kev_sha}}
            manifest = build(iter_osv_files(osv_zip), json.loads(kev_file.read_bytes()),
                             settings.db_dir("live"), embed_fn=embed_fn, sources=sources)
    else:
        raw = data_dir / "frozen" / "raw"
        kev_bytes = (raw / "kev.json").read_bytes()
        sources = {"osv": "data/frozen/raw/osv",
                   "kev": {"file": "data/frozen/raw/kev.json",
                           "sha256": hashlib.sha256(kev_bytes).hexdigest()}}
        manifest = build(iter_osv_files(raw / "osv"), json.loads(kev_bytes),
                         settings.db_dir("frozen"), embed_fn=embed_fn, sources=sources)

    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
