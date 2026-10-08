"""Pass marks for every exam, read from evals/thresholds.toml (D47).

A key ending in _max is an upper limit (score must be <= mark); any other key is a lower
limit (score must be >= mark).
"""
import tomllib
from pathlib import Path
from typing import NamedTuple

PATH = Path(__file__).parent / "thresholds.toml"


class Miss(NamedTuple):
    metric: str
    score: float
    mark: float
    upper: bool


def marks(exam: str, path: Path = PATH) -> list[tuple[str, float, bool]]:
    with path.open("rb") as f:
        table = tomllib.load(f)
    if exam not in table:
        raise KeyError(f"no pass marks for exam {exam!r} in {path.name}")
    return [(key.removesuffix("_max"), mark, key.endswith("_max"))
            for key, mark in table[exam].items()]


def check(exam: str, result: dict, path: Path = PATH) -> list[Miss]:
    """The metrics that missed their pass mark; empty means the exam passed."""
    misses = []
    for metric, mark, upper in marks(exam, path):
        if metric not in result:
            raise KeyError(f"exam {exam!r} did not report {metric!r}")
        score = result[metric]
        if (score > mark) if upper else (score < mark):
            misses.append(Miss(metric, score, mark, upper))
    return misses
