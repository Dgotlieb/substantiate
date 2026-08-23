"""The result of checking a single claim.

Every verdict carries the exact query that produced it. That is a hard
requirement, not a convenience: the tool reports findings rather than
judgements, and a maintainer must be able to re-run any check by hand and
disagree with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .claims import Claim


class Status(str, Enum):
    VERIFIED = "verified"
    """The claim corresponds to something that exists."""

    NOT_FOUND = "not_found"
    """The claim does not resolve. This is *not* a finding of fabrication --
    code gets renamed, branches go unlisted, path roots get omitted."""

    SKIPPED = "skipped"
    """Not checked: tier disabled, offline, or no resolver for this language."""

    ERROR = "error"
    """The check itself failed. Never counted against the report."""


@dataclass
class Verdict:
    claim: Claim
    status: Status
    detail: str
    """Short human-readable result, e.g. "no such path at v8.12.1"."""

    query: str
    """The reproducible check that was run, e.g. "git cat-file -e v8.12.1:src/x.c"."""

    hint: str | None = None
    """A near-miss that likely explains a NOT_FOUND, e.g. a file with the same
    basename elsewhere in the tree. Surfacing these is how the tool stays fair
    to genuine reports written against a moved or renamed target."""


@dataclass
class Result:
    """Everything checked for one report."""

    verdicts: list[Verdict] = field(default_factory=list)
    ref: str = "HEAD"
    repo_path: str = "."

    def by_status(self, status: Status) -> list[Verdict]:
        return [v for v in self.verdicts if v.status is status]

    def by_tier(self, tier: int) -> list[Verdict]:
        return [v for v in self.verdicts if v.claim.tier == tier]

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for v in self.verdicts:
            out[v.status.value] += 1
        return out

    @property
    def checked(self) -> int:
        return len(self.verdicts)
