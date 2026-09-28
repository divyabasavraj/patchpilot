"""Run the full ingest into a temporary folder, then swap it in."""
import json
import shutil
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .index import EmbedFn, build_index
from .injection import scan_text
from .kev import parse_kev
from .osv import parse_osv
from .store import write_db


def build(osv_files: Iterable[tuple[str, bytes]], kev_data: dict, out_dir: Path, *,
          embed_fn: EmbedFn, sources: dict) -> dict:
    kev = parse_kev(kev_data)   # fail fast, before any disk work

    advisories, withdrawn, malformed = [], 0, 0
    for _name, raw in osv_files:
        try:
            adv = parse_osv(json.loads(raw))
        except (ValueError, TypeError, KeyError, AttributeError):
            malformed += 1
            continue
        if adv is None:
            withdrawn += 1
            continue
        reason = scan_text(adv.summary + "\n" + adv.details)
        adv.flagged, adv.flag_reason = reason is not None, reason
        advisories.append(adv)

    searchable = [a for a in advisories if not a.id.startswith("MAL-")]

    tmp = out_dir.with_name(out_dir.name + ".building")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    try:
        write_db(tmp / "cve.db", advisories, kev)
        indexed = build_index(tmp / "chroma", searchable, embed_fn)
        manifest = {
            "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sources": sources,
            "advisories": len(advisories),
            "withdrawn": withdrawn,
            "malformed": malformed,
            "flagged": sum(a.flagged for a in advisories),
            "malware": len(advisories) - len(searchable),
            "indexed": indexed,
            "kev": len(kev),
        }
        (tmp / "manifest.json").write_text(json.dumps(manifest, indent=2))
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    swap_in(tmp, out_dir)
    return manifest


def swap_in(new_dir: Path, out_dir: Path) -> None:
    old = out_dir.with_name(out_dir.name + ".old")
    if old.exists():
        shutil.rmtree(old)
    if out_dir.exists():
        out_dir.rename(old)
    new_dir.rename(out_dir)
    if old.exists():
        shutil.rmtree(old)
