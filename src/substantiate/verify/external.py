"""Tier 2 verifiers: claims resolved against public registries.

Network-bound and therefore opt-in. Results are cacheable and worth caching:
the same fabricated CVE identifier tends to arrive repeatedly across reports.

v0.1 ships CVE (via OSV), CWE (via a bundled snapshot of the MITRE list) and
URL liveness. RFC section resolution and package-registry lookups are the
obvious next contributions -- each is one function with the same signature.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import re

from ..claims import Claim
from ..repo import Repo
from ..verdict import Status, Verdict

_TIMEOUT = 8

# The highest CWE identifier in the MITRE catalogue at the time of writing.
# Cheap sanity bound: a fabricated identifier is usually out of range or absent.
_CWE_MAX = 1440


def _get(url: str, method: str = "GET") -> tuple[int, bytes]:
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "substantiate"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.status, resp.read() if method == "GET" else b""


# -- Is this advisory about this project? -----------------------------------
#
# A CVE resolves as long as it exists, which answers a different question from
# the one a triager is asking. An invented identifier turned out to be a real
# Linux kernel bug, so a fabricated report about a Python project got a line
# that read like corroboration -- the one claim most worth challenging came
# back green.
#
# OSV already says what each advisory affects, so the answer is in hand. The
# verdict stays resolved either way: the identifier is real and saying
# otherwise would be false. What changes is that an advisory with no visible
# connection to this repository says so.

_MANIFEST_NAME = {
    "pyproject.toml": re.compile(r"^\s*name\s*=\s*[\"']([^\"']+)", re.MULTILINE),
    "setup.cfg": re.compile(r"^\s*name\s*=\s*(\S+)", re.MULTILINE),
    "Cargo.toml": re.compile(r"^\s*name\s*=\s*[\"']([^\"']+)", re.MULTILINE),
    "package.json": re.compile(r'"name"\s*:\s*"([^"]+)"'),
}


def _normalise(name: str) -> str:
    """PyPI folds these together and so must we, or the hint fires on honest text."""
    return re.sub(r"[-_.]+", "-", name.strip().lower()).strip("-")


def _project_names(repo: Repo) -> set[str]:
    """Every name this repository plausibly goes by."""
    names = {_normalise(repo.path.name)}
    for path, pattern in _MANIFEST_NAME.items():
        try:
            content = repo.read(path)
        except Exception:
            continue
        if not content:
            continue
        found = pattern.search(content)
        if found:
            names.add(_normalise(found.group(1)))
    # A scoped npm package is "@scope/thing"; the bare name is what matches.
    names |= {n.rsplit("/", 1)[-1] for n in names if "/" in n}
    return {n for n in names if n}


def _osv_relevance(data: dict, repo: Repo) -> str | None:
    """A hint when an advisory has no visible connection to this repository.

    Returns None whenever the answer is unclear, which includes an advisory
    that lists nothing at all. No affected list is not evidence of
    irrelevance, and an unhinted verdict beats a confidently wrong hint.
    """
    ours = _project_names(repo)
    packages: list[str] = []
    for entry in data.get("affected") or []:
        package = (entry.get("package") or {}).get("name")
        if package:
            packages.append(package)
            if _normalise(package) in ours:
                return None
        for span in entry.get("ranges") or []:
            location = span.get("repo") or ""
            if location and _normalise(location.rstrip("/").rsplit("/", 1)[-1]) in ours:
                return None
    if not packages:
        return None

    shown, seen = [], set()
    for name in packages:
        if name not in seen:
            seen.add(name)
            shown.append(name)
        if len(shown) == 3:
            break
    listed = ", ".join(shown)
    if len(seen) < len(packages) or len(packages) > len(shown):
        listed += ", and others"
    return f"published, but affects {listed} -- nothing this repository declares itself to be"


def verify_cve(claim: Claim, repo: Repo | None = None) -> Verdict:
    cve = claim.data["id"]
    query = f"https://api.osv.dev/v1/vulns/{cve}"
    try:
        status, body = _get(query)
        if status == 200:
            data = json.loads(body)
            summary = (data.get("summary") or "").strip()
            detail = f"published: {summary[:60]}" if summary else "published"
            hint = _osv_relevance(data, repo) if repo is not None else None
            return Verdict(claim, Status.VERIFIED, detail, query, hint=hint)
        return Verdict(claim, Status.NOT_FOUND, "absent from OSV", query)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return Verdict(
                claim,
                Status.NOT_FOUND,
                "absent from OSV",
                query,
                hint="unpublished or embargoed identifiers will also fail this check",
            )
        return Verdict(claim, Status.ERROR, f"OSV returned {exc.code}", query)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return Verdict(claim, Status.ERROR, f"lookup failed: {exc}", query)


def verify_cwe(claim: Claim) -> Verdict:
    number = claim.data["number"]
    query = f"https://cwe.mitre.org/data/definitions/{number}.html"
    if 1 <= number <= _CWE_MAX:
        return Verdict(claim, Status.VERIFIED, "within the MITRE catalogue", query)
    return Verdict(claim, Status.NOT_FOUND, "outside the MITRE catalogue", query)


def verify_url(claim: Claim) -> Verdict:
    url = claim.data["url"]
    try:
        status, _ = _get(url, method="HEAD")
        if 200 <= status < 400:
            return Verdict(claim, Status.VERIFIED, f"HTTP {status}", url)
        return Verdict(claim, Status.NOT_FOUND, f"HTTP {status}", url)
    except urllib.error.HTTPError as exc:
        return Verdict(claim, Status.NOT_FOUND, f"HTTP {exc.code}", url)
    except (urllib.error.URLError, TimeoutError) as exc:
        return Verdict(claim, Status.ERROR, f"unreachable: {exc}", url)


def verify_rfc(claim: Claim) -> Verdict:
    number = claim.data["number"]
    query = f"https://www.rfc-editor.org/rfc/rfc{number}.txt"
    section = claim.data.get("section")
    try:
        status, body = _get(query)
        if status != 200:
            return Verdict(claim, Status.NOT_FOUND, "no such RFC", query)
        if not section:
            return Verdict(claim, Status.VERIFIED, "document exists", query)
        text = body.decode("utf-8", errors="replace")
        if f"\n{section}." in text or f"\n{section} " in text or f"Section {section}" in text:
            return Verdict(claim, Status.VERIFIED, f"section {section} exists", query)
        return Verdict(claim, Status.NOT_FOUND, f"no section {section} in RFC {number}", query)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return Verdict(claim, Status.NOT_FOUND, "no such RFC", query)
        return Verdict(claim, Status.ERROR, f"returned {exc.code}", query)
    except (urllib.error.URLError, TimeoutError) as exc:
        return Verdict(claim, Status.ERROR, f"lookup failed: {exc}", query)
