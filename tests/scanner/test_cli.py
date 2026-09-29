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


def test_cli_prints_notes_about_bad_advisory_versions(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "netlib==4.0.0\n")
    build_fixture_db(tmp_path / "data" / "live" / "cve.db")
    assert main([str(req)]) == 1
    out = capsys.readouterr().out
    assert "Notes:" in out
    assert "PYSEC-net-1: advisory version '4.1.0-NA' is not a valid version; read as 4.1.0" in out


def test_cli_flags_malware_even_when_the_main_id_is_a_ghsa(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "django==4.0\nevilpkg==1.0\n")
    build_fixture_db(tmp_path / "data" / "live" / "cve.db")
    main([str(req)])
    first_row = capsys.readouterr().out.splitlines()[3]
    assert "GHSA-evil-1" in first_row and "MALWARE" in first_row


def test_cli_upgrade_wording(tmp_path, monkeypatch, capsys):
    req = setup(tmp_path, monkeypatch, "mixlib==1.0\nreqeusts==1.0\n")
    build_fixture_db(tmp_path / "data" / "live" / "cve.db")
    main([str(req)])
    out = capsys.readouterr().out
    assert "  mixlib 1.0 -> 1.5 (still affected by: GHSA-mix-2 \u2014 no fix known)" in out
    assert "  reqeusts 1.0: no fixed version known" in out
