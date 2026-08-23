"""Terminal output, for a maintainer triaging a private report locally."""

from __future__ import annotations

from ..verdict import Result, Status
from . import DISCLAIMER, TIER_TITLES, summary_line

_ANSI = {
    "dim": "\033[2m",
    "bold": "\033[1m",
    "green": "\033[32m",
    "red": "\033[31m",
    "reset": "\033[0m",
}

_LABEL = {
    Status.VERIFIED: "verified",
    Status.NOT_FOUND: "not found",
    Status.SKIPPED: "skipped",
    Status.ERROR: "error",
}

_COLOR = {
    Status.VERIFIED: "green",
    Status.NOT_FOUND: "red",
    Status.SKIPPED: "dim",
    Status.ERROR: "dim",
}

_RAW_WIDTH = 38


def render(result: Result, *, color: bool = True) -> str:
    def paint(text: str, style: str) -> str:
        return f"{_ANSI[style]}{text}{_ANSI['reset']}" if color else text

    lines = [f"{paint('SUBSTANTIATE', 'bold')}  {paint(summary_line(result), 'dim')}", ""]

    for tier in (1, 2):
        verdicts = result.by_tier(tier)
        if not verdicts:
            continue
        header = paint(TIER_TITLES[tier], "bold")
        suffix = paint(f"ref: {result.ref}", "dim") if tier == 1 else ""
        pad = max(1, 54 - len(TIER_TITLES[tier]))
        lines.append(f"{header}{' ' * pad}{suffix}".rstrip())

        for v in verdicts:
            label = paint(f"{_LABEL[v.status]:<10}", _COLOR[v.status])
            raw = v.claim.raw if len(v.claim.raw) <= _RAW_WIDTH else v.claim.raw[: _RAW_WIDTH - 1] + "…"
            lines.append(f"  {label} {raw:<{_RAW_WIDTH}} {paint(v.detail, 'dim')}")
            if v.hint:
                lines.append(f"  {' ' * 10} {' ' * _RAW_WIDTH} {paint('↳ ' + v.hint, 'dim')}")
        lines.append("")

    for note in result.notes:
        lines.append(paint(_wrap("note: " + note), "bold"))
        lines.append("")

    lines.append(paint(_wrap(DISCLAIMER), "dim"))
    return "\n".join(lines)


def _wrap(text: str, width: int = 76) -> str:
    words, out, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            out.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    out.append(cur)
    return "\n".join(out)
