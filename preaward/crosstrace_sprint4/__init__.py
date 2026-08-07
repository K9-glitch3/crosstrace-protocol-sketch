"""Development-only six-cell CrossTrace conformance harness."""

from .harness import run_matrix
from .model import CELL_SPECS, HARNESS_VERSION, RELEASE_ID, HarnessError

__all__ = [
    "CELL_SPECS",
    "HARNESS_VERSION",
    "RELEASE_ID",
    "HarnessError",
    "run_matrix",
]
