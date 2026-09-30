"""Scanner: requirements.txt in, vulnerability findings out. Plain code, no AI."""
from .requirements import parse_requirements
from .scan import scan

__all__ = ["parse_requirements", "scan"]
