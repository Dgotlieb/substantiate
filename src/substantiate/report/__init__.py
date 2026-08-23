"""Rendering verdicts for humans.

Copy is a correctness property in this project, not a matter of taste. The tool
reports findings; it never renders a judgement about a report or its author.
``DISCLAIMER`` must appear in every output format, and ``tests/test_report.py``
enforces that for every reporter -- including ones added later.

Forbidden vocabulary, checked by the same test: fake, fraudulent, bogus,
AI-generated, slop, spam, liar, invalid.
"""

from __future__ import annotations

from ..verdict import Result

DISCLAIMER = (
    "This is a triage signal, not a verdict. Claims can fail because code was "
    "renamed, the report targets an unlisted branch, or a path root was omitted. "
    "Every check above is reproducible."
)

BANNED_WORDS = (
    "fake", "fraudulent", "bogus", "ai-generated", "slop",
    "spam", "liar", "lying", "invalid", "fabricated",
)

TIER_TITLES = {1: "CODE REFERENCES", 2: "EXTERNAL REFERENCES"}


def render(result: Result, fmt: str = "terminal", *, color: bool = True) -> str:
    from . import jsonout, markdown, terminal

    if fmt == "terminal":
        return terminal.render(result, color=color)
    if fmt == "markdown":
        return markdown.render(result)
    if fmt == "json":
        return jsonout.render(result)
    raise ValueError(f"unknown format: {fmt}")


def summary_line(result: Result) -> str:
    c = result.counts
    parts = [f"{result.checked} claims checked"]
    for key, label in (
        ("verified", "verified"),
        ("not_found", "not found"),
        ("skipped", "skipped"),
        ("error", "errored"),
    ):
        if c[key]:
            parts.append(f"{c[key]} {label}")
    return " · ".join(parts)
