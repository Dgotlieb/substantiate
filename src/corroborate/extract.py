"""Deterministic claim extraction.

No model is involved here, by design. Every pattern below is a high-signal,
unambiguous surface form -- a path, a call, an identifier, a version. Prose
claims ("the parser fails to bounds-check the header") are deliberately out of
scope for v0.1; extracting those needs a model, which reintroduces
nondeterminism into the one part of the pipeline that must stay auditable.

Precision matters more than recall. A claim we fail to extract is a check that
does not run. A claim we invent is a finding against a contributor who never
made it.
"""

from __future__ import annotations

import re

from .claims import Claim, ClaimKind

# Extractors run in this order and claim their text exclusively: a URL swallows
# the paths and versions inside it before they can be matched on their own.
_FENCE = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)

_URL = re.compile(r"https?://[^\s<>()\[\]\"'`]+")
_CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
_CWE = re.compile(r"\bCWE-(\d{1,4})\b", re.IGNORECASE)
_RFC = re.compile(
    r"\bRFC[\s\-]?(\d{1,5})\b(?:\s*(?:§|section\s+|sec\.\s*)\s*([\d]+(?:\.\d+)*))?",
    re.IGNORECASE,
)

_SRC_EXT = (
    r"c|h|cc|cpp|cxx|hpp|py|pyi|js|mjs|cjs|ts|tsx|jsx|go|rs|java|kt|rb|php|"
    r"sh|bash|pl|swift|m|mm|cs|scala|lua|sql|md|rst|txt|yml|yaml|toml|json|cfg|ini"
)

# "lib/http2.c:1102" or "src/foo.py, line 42"
_LINE_REF = re.compile(
    rf"\b((?:[\w.+\-]+/)*[\w.+\-]+\.(?:{_SRC_EXT}))\s*(?::|,?\s+lines?\s+)(\d+)\b",
    re.IGNORECASE,
)
# "line 1102 of lib/http2.c"
_LINE_REF_PROSE = re.compile(
    rf"\blines?\s+(\d+)\s+(?:of|in)\s+((?:[\w.+\-]+/)*[\w.+\-]+\.(?:{_SRC_EXT}))\b",
    re.IGNORECASE,
)

_PATH = re.compile(rf"\b((?:[\w.+\-]+/)*[\w.+\-]+\.(?:{_SRC_EXT}))\b", re.IGNORECASE)

_SYMBOL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:(?:::|->|\.)[A-Za-z_][A-Za-z0-9_]*)*)\s*\(")

_VERSION_RANGE = re.compile(
    r"\bv?(\d+\.\d+(?:\.\d+)?)\s*(?:-|–|—|to|through|thru|up\s+to)\s*v?(\d+\.\d+(?:\.\d+)?)\b",
    re.IGNORECASE,
)
_VERSION = re.compile(r"\bv?(\d+\.\d+\.\d+(?:[\w.\-]*)?)\b")

_COMMIT = re.compile(r"\b([0-9a-f]{7,40})\b")

# An identifier is only treated as a call if it looks like code rather than an
# English word followed by a parenthesis.
_SYMBOL_STOPWORDS = frozenset(
    {
        "if", "for", "while", "switch", "return", "sizeof", "and", "or", "not",
        "in", "is", "the", "a", "an", "see", "e.g", "i.e", "note", "eg", "ie",
        "function", "method", "example", "print", "assert", "int", "char", "void",
    }
)


def _looks_like_symbol(name: str) -> bool:
    base = name.split("::")[-1].split(".")[-1].split("->")[-1]
    if base.lower() in _SYMBOL_STOPWORDS or len(base) < 3:
        return False
    if "_" in base or "::" in name or "->" in name:
        return True
    # CamelCase or lowerCamelCase reads as code; a lone lowercase word does not.
    return bool(re.search(r"[a-z][A-Z]", base)) or base[0].isupper()


class _Consumed:
    """Tracks text already claimed by a higher-priority extractor."""

    def __init__(self) -> None:
        self._spans: list[tuple[int, int]] = []

    def overlaps(self, start: int, end: int) -> bool:
        return any(start < e and end > s for s, e in self._spans)

    def take(self, start: int, end: int) -> None:
        self._spans.append((start, end))


def _code_spans(text: str) -> list[tuple[int, int]]:
    return [m.span() for m in _FENCE.finditer(text)]


def extract(text: str) -> list[Claim]:
    """Return every checkable claim in ``text``, in document order."""
    consumed = _Consumed()
    fences = _code_spans(text)
    claims: list[Claim] = []

    def in_code(start: int) -> bool:
        return any(s <= start < e for s, e in fences)

    def add(kind: ClaimKind, match: re.Match, data: dict, span: tuple[int, int] | None = None):
        start, end = span or match.span()
        if consumed.overlaps(start, end):
            return
        consumed.take(start, end)
        claims.append(
            Claim(
                kind=kind,
                raw=text[start:end],
                span=(start, end),
                data=data,
                in_code=in_code(start),
            )
        )

    # 1. URLs first -- they contain paths and versions that are not independent claims.
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        add(ClaimKind.URL, m, {"url": url}, span=(m.start(), m.start() + len(url)))

    # 2. Registry identifiers.
    for m in _CVE.finditer(text):
        add(ClaimKind.CVE, m, {"id": m.group(0).upper()})
    for m in _CWE.finditer(text):
        add(ClaimKind.CWE, m, {"id": m.group(0).upper(), "number": int(m.group(1))})
    for m in _RFC.finditer(text):
        add(ClaimKind.RFC, m, {"number": int(m.group(1)), "section": m.group(2)})

    # 3. Line references before bare paths, so "foo.c:12" is one claim not two.
    for m in _LINE_REF.finditer(text):
        add(ClaimKind.LINE_REF, m, {"path": m.group(1), "line": int(m.group(2))})
    for m in _LINE_REF_PROSE.finditer(text):
        add(ClaimKind.LINE_REF, m, {"path": m.group(2), "line": int(m.group(1))})

    # 4. Paths.
    for m in _PATH.finditer(text):
        add(ClaimKind.PATH, m, {"path": m.group(1)})

    # 5. Symbols.
    for m in _SYMBOL.finditer(text):
        name = m.group(1)
        if not _looks_like_symbol(name):
            continue
        add(ClaimKind.SYMBOL, m, {"name": name}, span=m.span(1))

    # 6. Versions: ranges emit both endpoints, since both are separately checkable.
    for m in _VERSION_RANGE.finditer(text):
        for group in (1, 2):
            add(ClaimKind.VERSION, m, {"version": m.group(group)}, span=m.span(group))
    for m in _VERSION.finditer(text):
        add(ClaimKind.VERSION, m, {"version": m.group(1)}, span=m.span(1))

    # 7. Commit SHAs. Requiring a digit rejects English hex-alikes ("deadbeef",
    # "accede") without needing a dictionary.
    for m in _COMMIT.finditer(text):
        sha = m.group(1)
        if not any(ch.isdigit() for ch in sha):
            continue
        add(ClaimKind.COMMIT, m, {"sha": sha})

    claims.sort(key=lambda c: c.span[0])
    return _dedupe(claims)


def _dedupe(claims: list[Claim]) -> list[Claim]:
    """Collapse repeated claims about the same thing, keeping first occurrence.

    A report that names the same nonexistent function eight times is one finding,
    not eight -- inflating the count would misrepresent the report.
    """
    seen: set[tuple[ClaimKind, str]] = set()
    out: list[Claim] = []
    for c in claims:
        key = (c.kind, _identity(c))
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _identity(claim: Claim) -> str:
    d = claim.data
    if claim.kind is ClaimKind.LINE_REF:
        return f"{d['path']}:{d['line']}"
    for field in ("path", "name", "version", "sha", "id", "url"):
        if field in d:
            return str(d[field]).lower()
    if claim.kind is ClaimKind.RFC:
        return f"{d['number']}#{d.get('section') or ''}"
    return claim.raw.lower()
