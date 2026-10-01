"""Pick a route for a question: rules first, the LLM only when rules don't decide (D8)."""
import json
import re
from collections.abc import Collection

from packaging.utils import canonicalize_name

from .. import llm
from ..config import Settings
from .models import Route

_ID_RE = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|MAL-\d{4}-\d+)\b",
    re.IGNORECASE)
_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# Package names that are also everyday words (D25): they count only with a cue.
AMBIGUOUS = frozenset("""
    accelerate black click dash distributed fabric feast flaw flower future glance hazard
    horizon intake keep late lightning llm markdown max notebook paste pip plane planet
    priority reflex safety salt sentry signify spam styling supervisor swift trickery
    trove tutor weave wheel""".split())
_ROUTER_PROMPT = (
    "You route questions for an assistant that answers questions about security "
    "vulnerabilities in Python packages. Reply with JSON only: {\"route\": \"concept\"} "
    "if answering needs a search of the vulnerability database (a kind of bug, attack or "
    "security problem), or {\"route\": \"chat\"} if it does not (greetings, thanks, "
    "general definitions such as 'what is a CVE?', questions about the assistant).")


def _normalise_id(raw: str) -> str:
    prefix, rest = raw.split("-", 1)
    prefix = prefix.upper()
    return f"{prefix}-{rest.lower() if prefix == 'GHSA' else rest.upper()}"


def find_ids(question: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_normalise_id(m) for m in _ID_RE.findall(question)))


def _cued(question: str, word: str) -> bool:
    """A common-word package name counts if quoted, versioned, or called a package."""
    w = re.escape(word)
    return bool(re.search(
        rf"`{w}`|['\"]{w}['\"]|\b{w}\s*(?:==|v?\d)|\b(?:package|library|module)\s+{w}\b"
        rf"|\b{w}\s+(?:package|library|module)\b", question, re.IGNORECASE))


def find_packages(question: str, known: Collection[str]) -> tuple[str, ...]:
    found = []
    for word in _WORD_RE.findall(question):
        word = word.rstrip("._-")
        name = canonicalize_name(word)
        if name in known and (name not in AMBIGUOUS or _cued(question, word)):
            found.append(name)
    return tuple(dict.fromkeys(found))


def _ask_llm(question: str, settings: Settings | None) -> Route:
    reply = llm.complete([{"role": "system", "content": _ROUTER_PROMPT},
                          {"role": "user", "content": question}], json_mode=True, settings=settings)
    try:
        kind = json.loads(reply).get("route")
    except (ValueError, AttributeError):
        kind = None
    if kind in ("concept", "chat"):
        return Route(kind, by="llm")
    return Route("concept", by="default")   # a needless search is harmless; a missed one is not


def route_question(question: str, known_packages: Collection[str], *,
                   settings: Settings | None = None) -> Route:
    ids, packages = find_ids(question), find_packages(question, known_packages)
    if ids:
        return Route("id", ids=ids, packages=packages)
    if packages:
        return Route("package", packages=packages)
    return _ask_llm(question, settings)
