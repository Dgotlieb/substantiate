"""Markdown output, for posting as a single comment on an issue or pull request.

Deliberately terse and collapsed by default. Maintainers dealing with a report
flood are already drowning in bot noise; a wall of green checkmarks for claims
that resolved fine is noise too. Verified claims are folded away, and only what
failed to resolve is visible without a click.
"""

from __future__ import annotations

from ..verdict import Result, Status
from . import DISCLAIMER, TIER_TITLES, summary_line

_MARK = {
    Status.VERIFIED: "resolved",
    Status.NOT_FOUND: "**not found**",
    Status.SKIPPED: "skipped",
    Status.ERROR: "check errored",
}


def render(result: Result) -> str:
    out = [f"**Substantiate** — {summary_line(result)}", ""]

    unresolved = result.by_status(Status.NOT_FOUND)
    if unresolved:
        out.append(f"Claims that did not resolve at `{result.ref}`:")
        out.append("")
        out.append("| Claim | Result | |")
        out.append("|---|---|---|")
        for v in unresolved:
            hint = v.hint or ""
            out.append(f"| `{_escape(v.claim.raw)}` | {v.detail} | {_escape(hint)} |")
        out.append("")
    else:
        out.append("Every extracted claim resolved against the repository.")
        out.append("")

    for note in result.notes:
        out.append(f"> [!NOTE]")
        out.append(f"> {note}")
        out.append("")

    resolved = [v for v in result.verdicts if v.status is not Status.NOT_FOUND]
    if resolved:
        out.append("<details>")
        out.append(f"<summary>All {len(result.verdicts)} claims checked</summary>")
        out.append("")
        for tier in (1, 2):
            verdicts = result.by_tier(tier)
            if not verdicts:
                continue
            out.append(f"**{TIER_TITLES[tier].title()}**")
            out.append("")
            for v in verdicts:
                out.append(f"- `{_escape(v.claim.raw)}` — {_MARK[v.status]}: {v.detail}")
                if v.query:
                    out.append(f"  - <sub>`{_escape(v.query)}`</sub>")
            out.append("")
        out.append("</details>")
        out.append("")

    out.append(f"<sub>{DISCLAIMER}</sub>")
    return "\n".join(out)


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'")
