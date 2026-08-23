"""Typed, falsifiable claims extracted from a report.

A Claim is a statement the report makes about the world that can be checked
against something authoritative: the repository, or a public registry. It is
deliberately *not* a statement about the report's author.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ClaimKind(str, Enum):
    # Tier 1 -- resolved against the repository. No network, no model.
    PATH = "path"
    SYMBOL = "symbol"
    LINE_REF = "line_ref"
    VERSION = "version"
    COMMIT = "commit"

    # Tier 2 -- resolved against public registries.
    CVE = "cve"
    CWE = "cwe"
    RFC = "rfc"
    URL = "url"
    PACKAGE = "package"


TIER_1 = frozenset(
    {ClaimKind.PATH, ClaimKind.SYMBOL, ClaimKind.LINE_REF, ClaimKind.VERSION, ClaimKind.COMMIT}
)
TIER_2 = frozenset({ClaimKind.CVE, ClaimKind.CWE, ClaimKind.RFC, ClaimKind.URL, ClaimKind.PACKAGE})


@dataclass(frozen=True)
class Claim:
    """One checkable assertion, tied back to the exact text that produced it."""

    kind: ClaimKind
    raw: str
    """The substring exactly as it appeared in the report."""

    span: tuple[int, int]
    """Character offsets into the report text, so output can quote the source."""

    data: dict = field(default_factory=dict)
    """Kind-specific parsed fields, e.g. {"path": "lib/http2.c", "line": 1102}."""

    in_code: bool = False
    """True when the claim was found inside a fenced code block. Callers may weight
    these differently: a path inside a stack trace is weaker evidence of intent than
    one in prose, but is still worth checking."""

    @property
    def tier(self) -> int:
        return 1 if self.kind in TIER_1 else 2

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.kind.value}:{self.raw}"
