"""Build the Chroma collection used for search by meaning."""
from collections.abc import Callable
from pathlib import Path

import chromadb

from .models import Advisory

EmbedFn = Callable[[list[str]], list[list[float]]]
COLLECTION = "advisories"
MAX_DOC_CHARS = 2000


def doc_text(adv: Advisory) -> str:
    text = "\n".join([
        adv.id,
        "Aliases: " + ", ".join(adv.aliases),
        "Packages: " + ", ".join(adv.packages),
        adv.summary,
        adv.details,
    ])
    return text[:MAX_DOC_CHARS]


def build_index(chroma_dir: Path, advisories: list[Advisory], embed_fn: EmbedFn,
                batch_size: int = 256) -> int:
    client = chromadb.PersistentClient(path=str(chroma_dir))
    try:
        col = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})
        for start in range(0, len(advisories), batch_size):
            batch = advisories[start:start + batch_size]
            texts = [doc_text(a) for a in batch]
            col.add(
                ids=[a.id for a in batch],
                documents=texts,
                embeddings=embed_fn(texts),
                metadatas=[{"id": a.id, "packages": ",".join(a.packages), "flagged": int(a.flagged)}
                           for a in batch],
            )
    finally:
        # Chroma caches one client per folder path. The build folder is renamed and later
        # reused, so drop the cache, or the next build sees a stale "collection exists".
        client.clear_system_cache()
    return len(advisories)
