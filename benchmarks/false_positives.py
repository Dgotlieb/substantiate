"""Measure the false-positive rate against a corpus known to be accurate.

The project's central risk is not missing fabricated reports. It is marking
down honest ones -- a contributor who cited a renamed function and got told
their reference does not exist will not file a second report, and a maintainer
who sees that happen once will uninstall.

So we measure. A project's own in-tree documentation is a useful proxy corpus:
it is maintainer-written, it references real code, and nobody generated it to
fool us. Every claim it makes that fails to resolve is either a true finding
(the docs drifted from the code) or a bug in this tool.

    python3 benchmarks/false_positives.py ~/src/curl docs
    python3 benchmarks/false_positives.py ~/src/cpython Doc --ext .rst

Treat the printed rate as an upper bound on false positives, never as the false
positive rate itself: real drift is common in old documentation, and confirming
which is which needs a human. The number to drive down is the *unexplained*
share -- misses with no hint attached.
"""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from corroborate.repo import Repo  # noqa: E402
from corroborate.verdict import Status  # noqa: E402
from corroborate.verify import check  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", help="path to a real checked-out repository")
    ap.add_argument("subdir", nargs="?", default="docs", help="documentation directory")
    ap.add_argument("--ext", default=".md", help="file extension to scan (default: .md)")
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--limit", type=int, default=0, help="stop after N documents")
    args = ap.parse_args(argv)

    repo = Repo(args.repo, args.ref)
    root = pathlib.Path(args.repo, args.subdir)
    if not root.is_dir():
        sys.exit(f"no such directory: {root}")

    docs = sorted(root.rglob(f"*{args.ext}"))
    if args.limit:
        docs = docs[: args.limit]
    if not docs:
        sys.exit(f"no *{args.ext} files under {root}")

    counts: collections.Counter[str] = collections.Counter()
    by_kind: collections.Counter[str] = collections.Counter()
    unexplained: list[str] = []
    explained = 0

    started = time.time()
    for doc in docs:
        result = check(doc.read_text(errors="replace"), repo)
        for v in result.verdicts:
            if v.claim.tier != 1:
                continue
            counts[v.status.value] += 1
            if v.status is not Status.NOT_FOUND:
                continue
            by_kind[v.claim.kind.value] += 1
            if v.hint:
                explained += 1
            else:
                unexplained.append(f"{v.claim.kind.value:<9} {v.claim.raw}")
    elapsed = time.time() - started

    checked = counts["verified"] + counts["not_found"]
    if not checked:
        sys.exit("no tier-1 claims found in this corpus")

    print(f"corpus        : {len(docs)} documents under {root}")
    print(f"tier-1 claims : {checked}")
    print(f"  verified    : {counts['verified']}")
    print(f"  not found   : {counts['not_found']}  ({100 * counts['not_found'] / checked:.1f}%)")
    print(f"    explained : {explained}  (a hint says why -- likely real drift)")
    print(f"  unexplained : {len(unexplained)}  ({100 * len(unexplained) / checked:.1f}%)  <- drive this down")
    print(f"time          : {elapsed:.1f}s  ({elapsed / len(docs):.2f}s per document)")

    if by_kind:
        print("\nmisses by kind:")
        for kind, n in by_kind.most_common():
            print(f"  {n:>4}  {kind}")

    if unexplained:
        print("\nunexplained misses (sample):")
        for line in sorted(set(unexplained))[:25]:
            print(f"  {line}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
