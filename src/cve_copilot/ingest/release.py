"""Nightly data as a GitHub release asset (spec 6, D50): one tarball of cve.db, chroma/ and
manifest.json, plus its SHA-256. CI packs it when the nightly exams pass; the app pulls it."""
import hashlib
import json
import shutil
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path

from .build import swap_in
from .sources import download

TAG = "data-latest"
ASSET = "cve-data.tar.gz"
REQUIRED = ("cve.db", "manifest.json", "chroma")


class ReleaseError(ValueError):
    """The archive is incomplete, corrupted or unsafe; the old data is kept."""


def release_url(repo: str, name: str = ASSET) -> str:
    return f"https://github.com/{repo}/releases/download/{TAG}/{name}"


def _missing(folder: Path) -> list[str]:
    return [name for name in REQUIRED if not (folder / name).exists()]


def _sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


def pack(db_dir: Path, out_dir: Path) -> Path:
    if missing := _missing(db_dir):
        raise ReleaseError(f"{db_dir} is missing {', '.join(missing)}")
    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / ASSET
    with tarfile.open(archive, "w:gz") as tf:
        for name in REQUIRED:
            tf.add(db_dir / name, arcname=name)
    (out_dir / f"{ASSET}.sha256").write_text(f"{_sha256(archive)}  {ASSET}\n")
    return archive


def unpack(archive: Path, expected_sha: str, out_dir: Path) -> dict:
    if _sha256(archive) != expected_sha.strip().lower():
        raise ReleaseError("checksum mismatch: the download is corrupted or was changed")
    tmp = out_dir.with_name(out_dir.name + ".building")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    try:
        with tarfile.open(archive, "r:gz") as tf:
            # "data" filter: no paths outside tmp, no links out, no device files (PEP 706).
            tf.extractall(tmp, filter="data")
        if missing := _missing(tmp):
            raise ReleaseError(f"archive is missing {', '.join(missing)}")
        manifest = json.loads((tmp / "manifest.json").read_text())
    except tarfile.TarError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ReleaseError(f"unsafe or broken archive: {e}") from e
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    swap_in(tmp, out_dir)
    return manifest


def pull(repo: str, out_dir: Path, *,
         downloader: Callable[[str, Path], str] = download) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        sha_file, archive = Path(tmp) / f"{ASSET}.sha256", Path(tmp) / ASSET
        downloader(release_url(repo, sha_file.name), sha_file)
        downloader(release_url(repo), archive)
        return unpack(archive, sha_file.read_text().split()[0], out_dir)
