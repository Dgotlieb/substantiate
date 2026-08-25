"""Substantiate — an evidence gate for open-source contributions.

Checks whether the claims in an issue, pull request, or security report
correspond to anything real, before a maintainer spends an hour proving they
don't.

It verifies claims, never authorship. See README.md.
"""

from __future__ import annotations

__version__ = "0.1.1"

from .claims import Claim, ClaimKind
from .extract import extract
from .repo import Repo, RepoError
from .verdict import Result, Status, Verdict
from .verify import check, run

__all__ = [
    "Claim",
    "ClaimKind",
    "Repo",
    "RepoError",
    "Result",
    "Status",
    "Verdict",
    "check",
    "extract",
    "run",
    "__version__",
]
