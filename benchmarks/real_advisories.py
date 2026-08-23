"""Measure against real, published, valid security advisories.

Documentation is a convenient proxy corpus but a harsh one: it drifts, it is
full of illustrative examples, and it references other projects. Security
advisories are the actual workload. curl publishes all of its own in OSV
format, with the prose writeup and the exact version affected, which makes them
the closest thing to ground truth available: every one is human-written, every
one was accepted as valid, and every claim in them was true of the release it
describes.

So any claim that fails to resolve here is a false positive, with one
controllable exception -- checking an advisory against the wrong revision. That
is what this harness exists to separate. It runs each advisory twice, once
against HEAD and once against the release the advisory itself names, and
reports both. The gap between them is the cost of not passing --ref.

    python3 benchmarks/real_advisories.py ~/src/curl
    python3 benchmarks/real_advisories.py ~/src/curl --limit 40

Requires a full clone: tags are needed to check out the affected release, and a
--depth 1 checkout has none.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from substantiate.repo import Repo, RepoError  # noqa: E402
from substantiate.verdict import Status  # noqa: E402
from substantiate.verify import check  # noqa: E402

VULN_JSON = "https://curl.se/docs/vuln.json"


def load_advisories(source: str) -> list[dict]:
    if source.startswith("http"):
        with urllib.request.urlopen(source, timeout=30) as resp:
            return json.load(resp)
    return json.loads(pathlib.Path(source).read_text())


def affected_version(advisory: dict) -> str | None:
    """The last release the advisory says is affected."""
    specific = advisory.get("database_specific") or {}
    if specific.get("last_affected"):
        return specific["last_affected"]
    for entry in advisory.get("affected") or []:
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                if "last_affected" in event:
                    return event["last_affected"]
    return None


def report_text(advisory: dict) -> str:
    parts = [advisory.get("summary") or "", advisory.get("details") or ""]
    return "\n\n".join(p for p in parts if p)


def tally(result) -> tuple[int, int, int]:
    """(checked, not_found, unexplained) over tier-1 claims."""
    checked = unresolved = unexplained = 0
    for v in result.verdicts:
        if v.claim.tier != 1 or v.status is Status.SKIPPED:
            continue
        checked += 1
        if v.status is Status.NOT_FOUND:
            unresolved += 1
            if not v.hint:
                unexplained += 1
    return checked, unresolved, unexplained


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", help="a full clone of curl (tags required)")
    ap.add_argument("--source", default=VULN_JSON, help="vuln.json URL or local path")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args(argv)

    advisories = load_advisories(args.source)
    if args.limit:
        advisories = advisories[: args.limit]

    head = Repo(args.repo, "HEAD")
    if not head.tags:
        sys.exit("repository has no tags: this needs a full clone, not --depth 1")

    totals = {"HEAD": collections.Counter(), "pinned": collections.Counter()}
    misses: collections.Counter[str] = collections.Counter()
    no_version = pinned_ok = 0

    for advisory in advisories:
        text = report_text(advisory)
        if not text.strip():
            continue

        checked, unresolved, unexplained = tally(check(text, head))
        totals["HEAD"].update(checked=checked, not_found=unresolved, unexplained=unexplained)

        version = affected_version(advisory)
        tag = head.find_tag(version) if version else None
        if tag is None:
            no_version += 1
            continue
        try:
            pinned = Repo(args.repo, tag)
        except RepoError:
            no_version += 1
            continue
        pinned_ok += 1

        result = check(text, pinned)
        checked, unresolved, unexplained = tally(result)
        totals["pinned"].update(checked=checked, not_found=unresolved, unexplained=unexplained)
        for v in result.verdicts:
            if v.status is Status.NOT_FOUND and not v.hint:
                misses[f"{v.claim.kind.value}: {v.claim.raw}"] += 1

    print(f"advisories        : {len(advisories)}")
    print(f"  pinned to a tag : {pinned_ok}")
    print(f"  no usable tag   : {no_version}\n")

    for label in ("HEAD", "pinned"):
        t = totals[label]
        checked = t["checked"] or 1
        title = "checked against HEAD" if label == "HEAD" else "checked against the affected release"
        print(f"{title}")
        print(f"  tier-1 claims   : {t['checked']}")
        print(f"  not found       : {t['not_found']}  ({100 * t['not_found'] / checked:.1f}%)")
        print(f"  unexplained     : {t['unexplained']}  ({100 * t['unexplained'] / checked:.1f}%)")
        print()

    if misses:
        print("unexplained misses when pinned (these are false positives):")
        for name, n in misses.most_common(20):
            print(f"  {n:>3}x  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
