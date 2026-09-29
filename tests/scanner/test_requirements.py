from cve_copilot.scanner.models import Pin
from cve_copilot.scanner.requirements import parse_requirements


def pins(text):
    return [(p.name, p.version, p.line_no) for p in parse_requirements(text).pins]


def notes(text, kind):
    return [(n.line_no, n.reason) for n in getattr(parse_requirements(text), kind)]


def test_simple_pins_with_canonical_names():
    text = "Django==4.2.0\nDjango_Rest.Framework==3.14.0\nflask == 2.2.0\n"
    assert pins(text) == [("django", "4.2.0", 1), ("django-rest-framework", "3.14.0", 2), ("flask", "2.2.0", 3)]


def test_pin_keeps_the_line_as_written():
    assert parse_requirements("flask==2.2.0  # web\n").pins == [Pin("flask", "2.2.0", 1, "flask==2.2.0")]


def test_comments_and_blank_lines_are_ignored():
    text = "# top comment\n\n   \nflask==2.2.0  # inline comment\n"
    parsed = parse_requirements(text)
    assert pins(text) == [("flask", "2.2.0", 4)]
    assert parsed.not_pinned == [] and parsed.skipped == []


def test_extras_and_markers_are_checked():
    text = "requests[socks]==2.19.0\npywin32==300; sys_platform == 'win32'\n"
    assert pins(text) == [("requests", "2.19.0", 1), ("pywin32", "300", 2)]


def test_unpinned_lines_are_reported():
    text = "flask\ndjango>=3,<4\nrequests~=2.0\nurllib3==1.*\nidna>=2,==2.8\n"
    assert pins(text) == []
    assert notes(text, "not_pinned") == [(1, "not pinned"), (2, "not pinned"), (3, "not pinned"),
                                         (4, "not pinned"), (5, "not pinned")]


def test_options_urls_and_paths_are_skipped():
    text = ("-r base.txt\n"
            "-e .\n"
            "--index-url https://pypi.org/simple\n"
            "git+https://github.com/psf/black.git\n"
            "pkg @ https://example.com/pkg-1.0.whl\n"
            "./local/pkg.whl\n"
            "!!! not a requirement\n")
    assert pins(text) == []
    assert notes(text, "skipped") == [
        (1, "pip option -r"), (2, "pip option -e"), (3, "pip option --index-url"),
        (4, "URL, VCS or local path"), (5, "URL, VCS or local path"), (6, "URL, VCS or local path"),
        (7, "could not parse")]


def test_pip_compile_hashes_and_continuations():
    text = ("flask==2.2.0 \\\n"
            "    --hash=sha256:aaaa \\\n"
            "    --hash=sha256:bbbb\n"
            "    # via -r requirements.in\n"
            "jinja2==3.1.2 \\\n"
            "    --hash=sha256:cccc\n")
    parsed = parse_requirements(text)
    assert pins(text) == [("flask", "2.2.0", 1), ("jinja2", "3.1.2", 5)]
    assert parsed.skipped == [] and parsed.not_pinned == []
    assert parsed.pins[0].line == "flask==2.2.0"


def test_bom_and_windows_line_endings():
    assert pins("﻿flask==2.2.0\r\njinja2==3.1.2\r\n") == [("flask", "2.2.0", 1), ("jinja2", "3.1.2", 2)]


def test_triple_equals():
    text = "foo===1.0\nbar===1.0-custom\n"
    assert pins(text) == [("foo", "1.0", 1)]
    assert notes(text, "skipped") == [(2, "version is not a valid Python version")]


def test_never_crashes_on_odd_input():
    text = "\\\n==\n[extras]\n;\n@\nflask==\n"
    parsed = parse_requirements(text)
    assert parsed.pins == []
