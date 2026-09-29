from cve_copilot.scanner.__main__ import main
from tests.scanner.fixture_db import build_fixture_db


def setup(tmp_path, monkeypatch, text):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path / "data"))
    req = tmp_path / "requirements.txt"
    req.write_text(text)
    return req


def test_cli_prints_findings_and_exits_1(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "flask==2.2.0\nflask\n-r base.txt\n")
    build_fixture_db(tmp_path / "data" / "live" / "cve.db")
    assert main([str(req)]) == 1
    out = capsys.readouterr().out
    assert "GHSA-flask-1" in out and "GHSA-flask-2" in out
    assert "flask 2.2.0 -> 3.1.3" in out
    assert "line 2" in out and "not pinned" in out
    assert "line 3" in out and "pip option -r" in out


def test_cli_clean_file_exits_0(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "flask==3.1.3\n")
    build_fixture_db(tmp_path / "data" / "frozen" / "db" / "cve.db")
    assert main([str(req), "--target", "frozen"]) == 0
    assert "No known vulnerabilities" in capsys.readouterr().out


def test_cli_missing_db(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "flask==2.2.0\n")
    assert main([str(req)]) == 2
    assert "Build it first" in capsys.readouterr().err
