import pytest

from evals import thresholds
from evals.thresholds import Miss, check, marks

TOML = """
[demo]
score = 0.90
errors_max = 0.05
"""


@pytest.fixture
def path(tmp_path):
    p = tmp_path / "t.toml"
    p.write_text(TOML)
    return p


def test_marks_strip_max_suffix(path):
    assert marks("demo", path) == [("score", 0.90, False), ("errors", 0.05, True)]


def test_on_the_mark_passes(path):
    assert check("demo", {"score": 0.90, "errors": 0.05}, path) == []


def test_lower_and_upper_limits(path):
    assert check("demo", {"score": 0.89, "errors": 0.06}, path) == [
        Miss("score", 0.89, 0.90, False), Miss("errors", 0.06, 0.05, True)]


def test_unknown_exam_is_an_error(path):
    with pytest.raises(KeyError, match="nope"):
        check("nope", {}, path)


def test_missing_metric_is_an_error(path):
    with pytest.raises(KeyError, match="score"):
        check("demo", {"errors": 0.0}, path)


def test_real_file_has_the_spec_marks():
    assert marks("scan") == [("accuracy", 1.0, False)]
    assert marks("retrieval") == [("recall_at_5", 0.90, False)]
    assert marks("answers") == [("citation_accuracy", 0.98, False), ("groundedness", 0.90, False)]
    assert marks("guards") == [("block_rate", 0.95, False), ("false_block_rate", 0.05, True)]
    assert thresholds.PATH.name == "thresholds.toml"
