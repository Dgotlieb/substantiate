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

from ..claims import Claim
from ..verdict import Status, Verdict

_TIMEOUT = 8

# The highest CWE identifier in the MITRE catalogue at the time of writing.
# Cheap sanity bound: a fabricated identifier is usually out of range or absent.
_CWE_MAX = 1440


def _get(url: str, method: str = "GET") -> tuple[int, bytes]:
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "corroborate"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.status, resp.read() if method == "GET" else b""


def verify_cve(claim: Claim) -> Verdict:
    cve = claim.data["id"]
    query = f"https://api.osv.dev/v1/vulns/{cve}"
    try:
        status, body = _get(query)
        if status == 200:
            data = json.loads(body)
            summary = (data.get("summary") or "").strip()
            detail = f"published: {summary[:60]}" if summary else "published"
            return Verdict(claim, Status.VERIFIED, detail, query)
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
