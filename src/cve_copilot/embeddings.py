"""One embedding model for ingest and search, so results match everywhere."""
from functools import lru_cache

MODEL_NAME = "BAAI/bge-small-en-v1.5"


@lru_cache(maxsize=1)
def _model():
    from fastembed import TextEmbedding   # slow import, only when needed
    return TextEmbedding(MODEL_NAME)


def embed(texts: list[str]) -> list[list[float]]:
    return [vec.tolist() for vec in _model().embed(texts)]
