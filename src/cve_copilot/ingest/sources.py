"""Where raw data comes from: downloads, zip files, folders."""
import hashlib
import zipfile
from collections.abc import Iterator
from pathlib import Path

import httpx

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def download(url: str, dest: Path, client: httpx.Client | None = None) -> str:
    client = client or httpx.Client(timeout=120, follow_redirects=True)
    sha = hashlib.sha256()
    with client.stream("GET", url) as resp:
        resp.raise_for_status()
        with dest.open("wb") as f:
            for chunk in resp.iter_bytes():
                f.write(chunk)
                sha.update(chunk)
    return sha.hexdigest()


def iter_osv_files(source: Path) -> Iterator[tuple[str, bytes]]:
    if source.suffix == ".zip":
        with zipfile.ZipFile(source) as zf:
            for name in sorted(n for n in zf.namelist() if n.endswith(".json")):
                yield name, zf.read(name)
    else:
        for path in sorted(source.glob("*.json")):
            yield path.name, path.read_bytes()
