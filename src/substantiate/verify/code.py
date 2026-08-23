"""Tier 1 verifiers: claims resolved against the repository.

No network, no model, no cache to warm. This tier is the default because it is
the cheapest and catches the most: a fabricated report tends to name files,
functions and releases that have never coexisted, and that is checkable in
milliseconds.

Each verifier returns the query it ran. If a maintainer disagrees with a
verdict, they must be able to paste that query into a shell and see for
themselves.
"""

from __future__ import annotations

from .. import builtins
from ..claims import Claim
from ..repo import Repo
from ..symbols import DEFAULT_RESOLVER, RegexSymbolResolver
from ..verdict import Status, Verdict


def verify_path(repo: Repo, claim: Claim) -> Verdict:
    path = claim.data["path"]
    query = f"git -C {repo.path.name} cat-file -e {repo.ref}:{path}"
    resolved = repo.resolve(path)
    if resolved:
        detail = "exists" if resolved == path.lstrip("./") else f"exists at {resolved}"
        return Verdict(claim, Status.VERIFIED, detail, query)

    elsewhere = repo.same_basename(path)
    hint = None
    if elsewhere:
        shown = ", ".join(elsewhere[:3])
        hint = f"a file of that name exists at {shown}"
    return Verdict(claim, Status.NOT_FOUND, f"no such path at {repo.ref}", query, hint)


def verify_symbol(
    repo: Repo, claim: Claim, resolver: RegexSymbolResolver = DEFAULT_RESOLVER
) -> Verdict:
    name = claim.data["name"]
    query = f"declaration of {name} in tracked sources at {repo.ref}"
    hits = resolver.find(repo, name)
    if hits:
        first = hits[0]
        extra = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
        return Verdict(claim, Status.VERIFIED, f"declared at {first}{extra}", query)

    # A name that belongs to the C library or a build system is not a claim
    # about this repository, and reporting it as missing is a false finding.
    external = builtins.origin(name) or builtins.stdlib_origin(name)
    if external:
        return Verdict(claim, Status.SKIPPED, f"{external}, not defined here", query)

    # "certifi.where", "ctx.load_default_certs", ".setLevel" -- an attribute of
    # something this repository does not define. Whether it exists is a question
    # about the other project or about a runtime type, and this tool cannot
    # answer it. Measured on urllib3, this was the largest single class of false
    # findings, because Python documentation is written in dotted calls.
    root = builtins.dotted_root(name)
    if root and not resolver.find(repo, root):
        return Verdict(
            claim, Status.SKIPPED, f"attribute of {root}, which is not defined here", query
        )
    if claim.data.get("attribute") and not root:
        return Verdict(
            claim, Status.SKIPPED, "attribute of an object the report does not name", query
        )

    hint = None
    misses = resolver.near_misses(repo, name)
    if misses:
        hint = f"closest declared symbols: {', '.join(misses)}"
    return Verdict(claim, Status.NOT_FOUND, "no matching declaration in tree", query, hint)


def verify_line_ref(repo: Repo, claim: Claim) -> Verdict:
    path, line = claim.data["path"], claim.data["line"]
    query = f"git -C {repo.path.name} show {repo.ref}:{path} | sed -n '{line}p'"
    count = repo.line_count(path)
    if count is None:
        elsewhere = repo.same_basename(path)
        hint = f"a file of that name exists at {elsewhere[0]}" if elsewhere else None
        return Verdict(claim, Status.NOT_FOUND, f"no such path at {repo.ref}", query, hint)
    if line <= count:
        return Verdict(claim, Status.VERIFIED, f"line exists ({count} total)", query)
    return Verdict(
        claim,
        Status.NOT_FOUND,
        f"file has {count} lines",
        query,
        hint="the file exists but is shorter than the cited line",
    )


def verify_version(repo: Repo, claim: Claim) -> Verdict:
    version = claim.data["version"]
    query = f"git -C {repo.path.name} tag --list | grep {version}"

    # Versions quoted inside code blocks are usually dependency pins from a
    # lockfile or a stack trace, not claims about this project's releases.
    if claim.in_code:
        return Verdict(claim, Status.SKIPPED, "inside a code block", query)
    if not repo.tags:
        return Verdict(claim, Status.SKIPPED, "repository has no tags", query)

    tag = repo.find_tag(version)
    if tag:
        return Verdict(claim, Status.VERIFIED, f"released as {tag}", query)
    return Verdict(
        claim,
        Status.NOT_FOUND,
        "no matching release tag",
        query,
        hint=f"{len(repo.tags)} tags exist; this version is not among them",
    )


def verify_commit(repo: Repo, claim: Claim) -> Verdict:
    sha = claim.data["sha"]
    query = f"git -C {repo.path.name} cat-file -e {sha}^{{commit}}"
    if not repo.is_git:
        return Verdict(claim, Status.SKIPPED, "not a git repository", query)
    if repo.has_commit(sha):
        return Verdict(claim, Status.VERIFIED, "object exists", query)
    return Verdict(
        claim,
        Status.NOT_FOUND,
        "not an object in this repository",
        query,
        hint="may reference a fork or an unrelated project",
    )
