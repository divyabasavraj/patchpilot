"""Turn one OSV JSON record into an Advisory."""
from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from packaging.utils import canonicalize_name

from .models import Advisory, AffectedRange

_CVSS_ORDER = [("CVSS_V3", CVSS3), ("CVSS_V4", CVSS4), ("CVSS_V2", CVSS2)]


def parse_osv(record: dict) -> Advisory | None:
    """Return None for withdrawn records; raise ValueError if malformed."""
    if not isinstance(record, dict) or not isinstance(record.get("id"), str):
        raise ValueError("OSV record has no string 'id'")
    if record.get("withdrawn"):
        return None

    ranges: list[AffectedRange] = []
    versions: list[tuple[str, str]] = []
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != "PyPI" or not pkg.get("name"):
            continue
        name = canonicalize_name(pkg["name"])
        for rng in aff.get("ranges", []):
            if rng.get("type") == "ECOSYSTEM":
                ranges.extend(_ranges_from_events(name, rng.get("events", [])))
        versions.extend((name, v) for v in aff.get("versions", []))

    vector, score = _cvss(record.get("severity", []))
    return Advisory(
        id=record["id"],
        summary=record.get("summary") or "",
        details=record.get("details") or "",
        published=record.get("published"),
        modified=record.get("modified"),
        cvss_vector=vector,
        cvss_score=score,
        aliases=list(record.get("aliases", [])),
        ranges=ranges,
        versions=versions,
        refs=[(r.get("type", ""), r["url"]) for r in record.get("references", []) if r.get("url")],
    )


def _ranges_from_events(package: str, events: list[dict]) -> list[AffectedRange]:
    """OSV events are ordered: introduced opens a range, fixed/last_affected closes it."""
    out: list[AffectedRange] = []
    start: str | None = None
    for event in events:
        if "introduced" in event:
            if start is not None:
                out.append(AffectedRange(package, start, None, None))
            start = event["introduced"]
        elif "fixed" in event:
            out.append(AffectedRange(package, start or "0", event["fixed"], None))
            start = None
        elif "last_affected" in event:
            out.append(AffectedRange(package, start or "0", None, event["last_affected"]))
            start = None
    if start is not None:
        out.append(AffectedRange(package, start, None, None))
    return out


def _cvss(severity: list[dict]) -> tuple[str | None, float | None]:
    """First vector that parses wins; if none parse, keep the first one without a score."""
    by_type = {s.get("type"): s.get("score") for s in severity}
    first_bad = None
    for kind, cls in _CVSS_ORDER:
        vector = by_type.get(kind)
        if vector:
            try:
                return vector, float(cls(vector).base_score)
            except CVSSError:
                first_bad = first_bad or vector
    return first_bad, None
