"""Pull advisory IDs and version strings out of text (pure code, shared with the output guard)."""
import re

from .router import find_ids

__all__ = ["find_ids", "find_versions", "unsupported_versions"]

_VERSION_RE = re.compile(r"(?<![\w.-])\d+(?:\.\d+)+(?:(?:a|b|rc|\.post|\.dev)\d+)?(?![\w-])")


def find_versions(text: str) -> tuple[str, ...]:
    """Dotted version numbers such as 2.2.5 or 3.1.3rc1 (not dates, not IDs), no repeats."""
    return tuple(dict.fromkeys(m.rstrip(".") for m in _VERSION_RE.findall(text)))


def unsupported_versions(text: str, source_text: str) -> tuple[str, ...]:
    known = set(find_versions(source_text))
    return tuple(v for v in find_versions(text) if v not in known)
