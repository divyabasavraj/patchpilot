"""Router + retriever (Phase 3); grader, generator and guards join in later phases."""
from pathlib import Path

from ..config import Settings
from ..embeddings import embed
from .models import Doc, Route
from .retriever import EmbedFn, package_names, retrieve
from .router import route_question

__all__ = ["Doc", "Route", "retrieve", "route_question", "search"]


def search(question: str, db_dir: Path, *, k: int = 5, embed_fn: EmbedFn = embed,
           settings: Settings | None = None) -> tuple[Route, list[Doc]]:
    """Route the question, then fetch its documents."""
    route = route_question(question, package_names(db_dir / "cve.db"), settings=settings)
    return route, retrieve(route, question, db_dir, k=k, embed_fn=embed_fn)
