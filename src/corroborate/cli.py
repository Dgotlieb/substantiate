"""Command line entry point.

    corroborate check report.md --repo ~/src/curl --ref v8.12.1
    gh issue view 4471 --json body -q .body | corroborate check - --repo .

Exit status is 0 even when claims do not resolve. That is deliberate: this tool
produces a triage signal for a human, and a non-zero exit invites people to wire
it up as an auto-close gate, which is the one use it must not have. Automation
that genuinely wants to branch on the outcome can opt in with --exit-code, and
should read the JSON rather than the exit status.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .extract import extract
from .report import render
from .repo import Repo, RepoError
from .verdict import Status
from .verify import run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corroborate",
        description="Check whether the claims in a report correspond to anything real.",
    )
    parser.add_argument("--version", action="version", version=f"corroborate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="verify a report against a repository")
    check.add_argument("report", help="path to the report, or - for stdin")
    check.add_argument("--repo", default=".", help="repository to check against (default: .)")
    check.add_argument("--ref", default="HEAD", help="ref the report claims to describe")
    check.add_argument(
        "--format", default="terminal", choices=("terminal", "markdown", "json")
    )
    check.add_argument(
        "--online",
        action="store_true",
        help="also run tier 2 checks, which query public registries",
    )
    check.add_argument("--no-color", action="store_true")
    check.add_argument(
        "--exit-code",
        action="store_true",
        help="exit 1 if any claim did not resolve (off by default; see --help)",
    )

    extract_cmd = sub.add_parser("extract", help="print extracted claims without checking them")
    extract_cmd.add_argument("report", help="path to the report, or - for stdin")

    return parser


def _read(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    try:
        with open(source, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        sys.exit(f"corroborate: cannot read {source}: {exc}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    text = _read(args.report)

    if args.command == "extract":
        for claim in extract(text):
            print(f"{claim.kind.value:<10} {claim.raw}")
        return 0

    try:
        repo = Repo(args.repo, args.ref)
    except RepoError as exc:
        sys.exit(f"corroborate: {exc}")

    tiers = {1, 2} if args.online else {1}
    result = run(extract(text), repo, tiers=tiers)
    print(render(result, args.format, color=not args.no_color and sys.stdout.isatty()))

    if args.exit_code and result.by_status(Status.NOT_FOUND):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
