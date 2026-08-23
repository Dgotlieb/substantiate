"""Dispatch a set of claims to the verifier that knows how to check each one."""

from __future__ import annotations

from ..claims import Claim, ClaimKind
from ..extract import extract
from ..repo import Repo
from ..symbols import DEFAULT_RESOLVER, RegexSymbolResolver
from ..verdict import Result, Status, Verdict
from . import code, external

__all__ = ["check", "run", "VERIFIERS"]

VERIFIERS = {
    ClaimKind.PATH: 1,
    ClaimKind.SYMBOL: 1,
    ClaimKind.LINE_REF: 1,
    ClaimKind.VERSION: 1,
    ClaimKind.COMMIT: 1,
    ClaimKind.CVE: 2,
    ClaimKind.CWE: 2,
    ClaimKind.RFC: 2,
    ClaimKind.URL: 2,
}


def run(
    claims: list[Claim],
    repo: Repo,
    *,
    tiers: set[int] = frozenset({1}),
    resolver=None,
) -> Result:
    if resolver is None:
        # Resolved per call rather than at import: the tree-sitter extra may be
        # installed after this module is first imported, and importing it
        # eagerly would make the zero-dependency path pay for an optional one.
        from ..treesitter import best_resolver

        resolver = best_resolver()
    result = Result(ref=repo.ref, repo_path=str(repo.path))
    for claim in claims:
        tier = VERIFIERS.get(claim.kind)
        if tier is None:
            continue
        if tier not in tiers:
            result.verdicts.append(
                Verdict(claim, Status.SKIPPED, f"tier {tier} not enabled", query="")
            )
            continue
        result.verdicts.append(_dispatch(claim, repo, resolver))
    return result


def _dispatch(claim: Claim, repo: Repo, resolver) -> Verdict:
    try:
        if claim.kind is ClaimKind.PATH:
            return code.verify_path(repo, claim)
        if claim.kind is ClaimKind.SYMBOL:
            return code.verify_symbol(repo, claim, resolver)
        if claim.kind is ClaimKind.LINE_REF:
            return code.verify_line_ref(repo, claim)
        if claim.kind is ClaimKind.VERSION:
            return code.verify_version(repo, claim)
        if claim.kind is ClaimKind.COMMIT:
            return code.verify_commit(repo, claim)
        if claim.kind is ClaimKind.CVE:
            return external.verify_cve(claim)
        if claim.kind is ClaimKind.CWE:
            return external.verify_cwe(claim)
        if claim.kind is ClaimKind.RFC:
            return external.verify_rfc(claim)
        if claim.kind is ClaimKind.URL:
            return external.verify_url(claim)
    except Exception as exc:  # a broken verifier must never indict a report
        return Verdict(claim, Status.ERROR, f"check failed: {exc}", query="")
    return Verdict(claim, Status.SKIPPED, "no verifier", query="")


def check(text: str, repo: Repo, *, tiers: set[int] = frozenset({1}), resolver=None) -> Result:
    """Extract claims from ``text`` and verify them against ``repo``."""
    return run(extract(text), repo, tiers=tiers, resolver=resolver)
