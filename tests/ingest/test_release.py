import hashlib
import io
import json
import tarfile

import httpx
import pytest

from cve_copilot.ingest import release
from cve_copilot.ingest.__main__ import main


def make_db_dir(path, built_at="2026-10-11T02:00:00+00:00"):
    (path / "chroma").mkdir(parents=True)
    (path / "chroma" / "index.bin").write_bytes(b"vectors")
    (path / "cve.db").write_bytes(b"sqlite")
    (path / "manifest.json").write_text(json.dumps({"built_at": built_at}))
    return path


def test_pack_then_unpack_round_trip(tmp_path):
    archive = release.pack(make_db_dir(tmp_path / "live"), tmp_path / "dist")
    sha = (tmp_path / "dist" / "cve-data.tar.gz.sha256").read_text().split()[0]
    assert sha == hashlib.sha256(archive.read_bytes()).hexdigest()
    out = tmp_path / "app" / "live"
    out.mkdir(parents=True)
    (out / "cve.db").write_bytes(b"old")
    manifest = release.unpack(archive, sha, out)
    assert manifest["built_at"].startswith("2026-10-11")
    assert (out / "cve.db").read_bytes() == b"sqlite"
    assert (out / "chroma" / "index.bin").read_bytes() == b"vectors"
    assert not out.with_name("live.building").exists()


def test_pack_refuses_an_incomplete_folder(tmp_path):
    (tmp_path / "live").mkdir()
    (tmp_path / "live" / "cve.db").write_bytes(b"x")
    with pytest.raises(release.ReleaseError, match="manifest.json"):
        release.pack(tmp_path / "live", tmp_path / "dist")


def test_unpack_rejects_a_wrong_checksum_and_keeps_old_data(tmp_path):
    archive = release.pack(make_db_dir(tmp_path / "live"), tmp_path / "dist")
    out = tmp_path / "app"
    out.mkdir()
    (out / "cve.db").write_bytes(b"old")
    with pytest.raises(release.ReleaseError, match="checksum"):
        release.unpack(archive, "0" * 64, out)
    assert (out / "cve.db").read_bytes() == b"old"


def tar_with(tmp_path, members):
    path = tmp_path / "bad.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_unpack_blocks_paths_outside_the_folder(tmp_path):
    # A tampered archive must not write outside the data folder (tarfile "data" filter).
    archive, sha = tar_with(tmp_path, [("../escaped.txt", b"x"), ("cve.db", b"db")])
    with pytest.raises(release.ReleaseError):
        release.unpack(archive, sha, tmp_path / "out" / "live")
    assert not (tmp_path / "out" / "escaped.txt").exists()
    assert not (tmp_path / "out" / "live").exists()


def test_unpack_rejects_missing_files(tmp_path):
    archive, sha = tar_with(tmp_path, [("cve.db", b"db")])
    with pytest.raises(release.ReleaseError, match="manifest.json"):
        release.unpack(archive, sha, tmp_path / "out" / "live")
    assert not (tmp_path / "out" / "live.building").exists()


def serve_release(tmp_path):
    archive = release.pack(make_db_dir(tmp_path / "src"), tmp_path / "dist")
    files = {"cve-data.tar.gz": archive.read_bytes(),
             "cve-data.tar.gz.sha256": (tmp_path / "dist" / "cve-data.tar.gz.sha256").read_bytes()}
    urls = []

    def downloader(url, dest):
        urls.append(url)
        dest.write_bytes(files[url.rsplit("/", 1)[1]])
        return hashlib.sha256(dest.read_bytes()).hexdigest()
    return downloader, urls


def test_cli_pull_release(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CVE_RELEASE_REPO", "someone/cve-copilot")
    downloader, urls = serve_release(tmp_path)
    assert main(["--pull-release"], downloader=downloader) == 0
    assert urls[0] == ("https://github.com/someone/cve-copilot/releases/download/data-latest/"
                       "cve-data.tar.gz.sha256")
    assert (tmp_path / "data" / "live" / "cve.db").read_bytes() == b"sqlite"
    assert "2026-10-11" in capsys.readouterr().out


def test_cli_pull_release_failure_keeps_old_data(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    (tmp_path / "live").mkdir()
    (tmp_path / "live" / "cve.db").write_text("old")

    def no_release(url, dest):
        raise httpx.HTTPStatusError("404", request=httpx.Request("GET", url),
                                    response=httpx.Response(404))
    assert main(["--pull-release"], downloader=no_release) == 1
    assert "Pull failed" in capsys.readouterr().err
    assert (tmp_path / "live" / "cve.db").read_text() == "old"


def test_cli_pack_release(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    make_db_dir(tmp_path / "live")
    assert main(["--pack-release", str(tmp_path / "dist")]) == 0
    assert (tmp_path / "dist" / "cve-data.tar.gz").exists()
