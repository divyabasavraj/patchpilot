"""Advisory IDs: which stored records are the same bug, and which ID to show first."""
from collections import defaultdict
from collections.abc import Iterable

_ID_RANK = {"GHSA": 0, "PYSEC": 1}   # which ID to show first when a bug has several


def group_ids(pairs: Iterable[tuple[str, Iterable[str]]]) -> list[list[str]]:
    """Record IDs that share any ID or alias describe the same bug (e.g. GHSA + PYSEC)."""
    pairs = [(rid, list(aliases)) for rid, aliases in pairs]
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for rid, aliases in pairs:
        for alias in aliases:
            parent[find(alias)] = find(rid)
    groups: dict[str, list[str]] = defaultdict(list)
    for rid, _ in pairs:
        groups[find(rid)].append(rid)
    return sorted((sorted(set(g)) for g in groups.values()), key=lambda g: g[0])


def main_id(ids: Iterable[str]) -> str:
    return min(ids, key=lambda i: (_ID_RANK.get(i.split("-")[0], 9), i))
