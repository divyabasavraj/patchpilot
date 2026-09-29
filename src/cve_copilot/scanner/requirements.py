"""Read a requirements.txt into pinned packages, unpinned lines and skipped lines."""
import re
from collections.abc import Iterator

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import LineNote, ParsedRequirements, Pin

_COMMENT = re.compile(r"(^|\s)#.*$")       # "#" at the start or after a space (not inside URLs)
_COMMENT_LINE = re.compile(r"\s*#")        # a whole-line comment (pip never continues it)
_HASH = re.compile(r"\s--hash[=\s]\S+")    # pip-compile: --hash=sha256:...
_VCS = ("git+", "hg+", "svn+", "bzr+")


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield (first line number, text), joining lines that end with a backslash like pip:
    parts are joined with no separator, and a comment line is never continued."""
    parts: list[str] = []
    start = 0
    for no, raw in enumerate(text.lstrip("\ufeff").splitlines(), start=1):
        if not parts:
            start = no
        comment = _COMMENT_LINE.match(raw) is not None
        if raw.endswith("\\") and not comment:
            parts.append(raw[:-1])
            continue
        parts.append(" " + raw if comment else raw)
        yield start, "".join(parts)
        parts = []
    if parts:
        yield start, "".join(parts)


def parse_requirements(text: str) -> ParsedRequirements:
    out = ParsedRequirements()
    for no, raw in _logical_lines(text):
        line = _HASH.sub("", _COMMENT.sub("", raw)).strip()
        if line:
            _classify(no, line, out)
    return out


def _classify(no: int, line: str, out: ParsedRequirements) -> None:
    if line.startswith("-"):
        option = line.split()[0].split("=")[0]
        out.skipped.append(LineNote(no, line, f"pip option {option}"))
        return
    try:
        req = Requirement(line)
    except InvalidRequirement:
        looks_like_path = line.startswith(_VCS) or line.startswith(".") or "/" in line
        out.skipped.append(LineNote(no, line, "URL, VCS or local path" if looks_like_path
                                    else "could not parse"))
        return
    if req.url:
        out.skipped.append(LineNote(no, line, "URL, VCS or local path"))
        return
    specs = list(req.specifier)
    if len(specs) != 1 or specs[0].operator not in ("==", "===") or "*" in specs[0].version:
        out.not_pinned.append(LineNote(no, line, "not pinned"))
        return
    try:
        Version(specs[0].version)
    except InvalidVersion:
        out.skipped.append(LineNote(no, line, "version is not a valid Python version"))
        return
    out.pins.append(Pin(canonicalize_name(req.name), specs[0].version, no, line))
