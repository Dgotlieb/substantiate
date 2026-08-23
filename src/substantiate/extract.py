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

# A leading "\b" cannot match before a dot, which silently truncated dotfile
# directories: ".github/workflows/ci.yml" was extracted as
# "github/workflows/ci.yml", a path that then correctly failed to resolve. The
# lookbehind anchors at a real boundary instead.
_PATH_START = r"(?<![\w./])"

# "lib/http2.c:1102" or "src/foo.py, line 42"
_LINE_REF = re.compile(
    rf"{_PATH_START}((?:[\w.+\-]+/)*[\w.+\-]+\.(?:{_SRC_EXT}))\s*(?::|,?\s+lines?\s+)(\d+)\b",
    re.IGNORECASE,
)
# "line 1102 of lib/http2.c"
_LINE_REF_PROSE = re.compile(
    rf"\blines?\s+(\d+)\s+(?:of|in)\s+((?:[\w.+\-]+/)*[\w.+\-]+\.(?:{_SRC_EXT}))\b",
    re.IGNORECASE,
)

# A path claim requires a separator. Documentation is full of illustrative bare
# filenames -- "cookies.txt", "file.txt", "node.js" -- which are not assertions
# that the repository contains them. Measured against curl's own docs, dropping
# bare filenames removes a large block of false positives and costs almost no
# real recall, since reports naming a source file normally give its directory.
_PATH = re.compile(
    rf"{_PATH_START}((?:[\w.+\-]+/)+[\w.+\-]+\.(?:{_SRC_EXT}))\b", re.IGNORECASE
)

# The identifier must abut its parenthesis. Prose writes "OpenSSL (and its
# forks)" and "the parser (see below)"; code writes "Curl_hpack_decode(". That
# single space is the most reliable separator between the two available without
# parsing, and removing it was worth more than every other precision rule here.
_SYMBOL = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:(?:::|->|\.)[A-Za-z_][A-Za-z0-9_]*)*)\(\s*(\))?"
)

# Named constants: CURLOPT_SSH_KNOWNHOSTS, CURLE_PEER_FAILED_VERIFICATION,
# SSL_VERIFYPEER. Measured against curl's 206 published advisories, these are
# the most-cited checkable thing in a real security report by a wide margin --
# advisories describe behaviour in prose and name the API, rather than pointing
# at files and line numbers the way a fabricated report tends to.
#
# Requiring an underscore is what separates an identifier from an acronym: SSH,
# URL, TLS and SFTP are prose, CURLOPT_SSH_KNOWNHOSTS is a declaration.
_CONSTANT = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")

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
        # Language keywords. These reach the extractor from code fences and read
        # as calls because they are routinely followed by a parenthesis.
        "else", "elif", "case", "do", "goto", "break", "continue", "struct",
        "enum", "union", "static", "const", "class", "def", "try", "except",
        "finally", "with", "import", "from", "public", "private", "protected",
        "new", "delete", "throw", "catch", "typedef", "extern", "unsigned",
        "signed", "long", "short", "float", "double", "bool", "auto", "var",
        "let", "func", "fn", "impl", "match", "use", "mod", "pub", "defer",
    }
)


def _looks_like_symbol(name: str, empty_parens: bool = False) -> bool:
    base = name.split("::")[-1].split(".")[-1].split("->")[-1]
    if base.lower() in _SYMBOL_STOPWORDS or len(base) < 3:
        return False
    if "_" in base or "::" in name or "->" in name:
        return True
    if empty_parens:
        return True
    # lowerCamelCase reads as a call. A capitalised word does not: "OpenSSL",
    # "Schannel", "NTLM" and "Boolean" are products, protocols and types, and
    # treating them as undeclared functions is the single largest source of
    # false findings against honest documentation.
    return base[0].islower() and any(c.isupper() for c in base)


# Underscored capitals that are conventions rather than declarations.
_CONSTANT_STOPWORDS = frozenset(
    {
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "FTP_PROXY",
        "LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH", "PKG_CONFIG_PATH",
        "PATH_MAX", "NAME_MAX", "SSL_CERT_FILE", "SSL_CERT_DIR", "TMPDIR",
        "GITHUB_TOKEN", "HOME_DIR", "USER_AGENT", "CONTENT_TYPE",
        "CONTENT_LENGTH", "TRANSFER_ENCODING", "SET_COOKIE", "TODO_LIST",
    }
)


def _looks_like_host(path: str) -> bool:
    """True for schemeless URLs such as ``example.com/moo2.txt``.

    Documentation is full of these, especially in a tool whose whole subject is
    fetching URLs, and reading the hostname as a directory turns every one into
    a false finding. A leading dot is fine (``.github/workflows/ci.yml``); an
    interior dot in the first segment means a hostname.
    """
    first = path.lstrip("./").split("/", 1)[0]
    return "." in first


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
        if _looks_like_host(m.group(1)):
            continue
        add(ClaimKind.PATH, m, {"path": m.group(1)})

    # 5. Symbols.
    for m in _SYMBOL.finditer(text):
        name = m.group(1)
        if not _looks_like_symbol(name, empty_parens=bool(m.group(2))):
            continue
        # ".setLevel(" is a method on some object the report never names. The
        # leading dot is the only evidence of that, and it is outside the
        # capture, so record it here or the receiver is lost.
        start = m.start(1)
        attribute = start > 0 and text[start - 1] == "."
        add(ClaimKind.SYMBOL, m, {"name": name, "attribute": attribute}, span=m.span(1))

    # 6. Named constants, after calls so "FOO_BAR()" is claimed once as a symbol.
    for m in _CONSTANT.finditer(text):
        name = m.group(1)
        if len(name) < 6 or name in _CONSTANT_STOPWORDS:
            continue
        add(ClaimKind.SYMBOL, m, {"name": name, "attribute": False, "constant": True})

    # 7. Versions: ranges emit both endpoints, since both are separately checkable.
    for m in _VERSION_RANGE.finditer(text):
        for group in (1, 2):
            add(ClaimKind.VERSION, m, {"version": m.group(group)}, span=m.span(group))
    for m in _VERSION.finditer(text):
        add(ClaimKind.VERSION, m, {"version": m.group(1)}, span=m.span(1))

    # 7. Commit SHAs. A real abbreviated SHA effectively always mixes digits and
    # letters: requiring both rejects English hex-alikes ("deadbeef", "accede")
    # and, just as importantly, bare numbers like the date "20190808".
    for m in _COMMIT.finditer(text):
        sha = m.group(1)
        if not any(ch.isdigit() for ch in sha) or not any(ch in "abcdef" for ch in sha):
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
