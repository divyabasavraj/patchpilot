import hashlib
import zipfile

import httpx
import pytest

from cve_copilot.ingest.sources import download, iter_osv_files


def test_download_writes_file_and_returns_sha(tmp_path):
    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b"hello")))
    sha = download("https://example.com/f", tmp_path / "f", client=client)
    assert (tmp_path / "f").read_bytes() == b"hello"
    assert sha == hashlib.sha256(b"hello").hexdigest()


def test_download_raises_on_http_error(tmp_path):
    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(500)))
    with pytest.raises(httpx.HTTPError):
        download("https://example.com/f", tmp_path / "f", client=client)


def test_iter_zip_and_dir(tmp_path):
    z = tmp_path / "all.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("B.json", b"{}")
        zf.writestr("A.json", b"[]")
    assert list(iter_osv_files(z)) == [("A.json", b"[]"), ("B.json", b"{}")]

    d = tmp_path / "dir"
    d.mkdir()
    (d / "X.json").write_bytes(b"{}")
    (d / "notes.txt").write_bytes(b"skip me")
    assert list(iter_osv_files(d)) == [("X.json", b"{}")]
