import json
import sqlite3

import httpx

from cve_copilot.ingest.__main__ import main


def fake_embed(texts):
    return [[1.0, 0.0] for _ in texts]


def write_frozen(data_dir):
    raw = data_dir / "frozen" / "raw"
    (raw / "osv").mkdir(parents=True)
    (raw / "osv" / "GHSA-1.json").write_text(json.dumps({"id": "GHSA-1", "affected": []}))
    (raw / "kev.json").write_text(json.dumps({"vulnerabilities": []}))


def test_frozen_target_builds_from_committed_raw(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    write_frozen(tmp_path)
    assert main(["--target", "frozen"], embed_fn=fake_embed) == 0
    con = sqlite3.connect(tmp_path / "frozen" / "db" / "cve.db")
    assert con.execute("SELECT id FROM advisories").fetchall() == [("GHSA-1",)]


def test_live_download_failure_keeps_old_data(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path))
    (tmp_path / "live").mkdir()
    (tmp_path / "live" / "cve.db").write_text("old")

    def failing_download(url, dest):
        raise httpx.ConnectError("no internet")

    assert main(["--target", "live"], embed_fn=fake_embed, downloader=failing_download) == 1
    assert "Download failed" in capsys.readouterr().err
    assert (tmp_path / "live" / "cve.db").read_text() == "old"
