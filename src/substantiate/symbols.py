"""Symbol resolution.

A report saying ``Curl_hpack_decode()`` is claiming a *declaration* exists, not
that a string appears somewhere. Matching the bare name would let a mention in a
comment -- or in the report's own quoted diff -- substantiate itself, which is
exactly the failure mode this tool exists to catch.

The regex resolver below is the v0.1 default because it has no dependencies and
handles the shapes that matter. ``SymbolResolver`` is the seam where a
tree-sitter backend plugs in: implement ``find`` for a language and everything
else -- extraction, verdicts, reporting -- is unchanged. See CONTRIBUTING.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from .repo import Repo


@dataclass(frozen=True)
class Location:
    path: str
    line: int

    def __str__(self) -> str:
        return f"{self.path}:{self.line}"


class SymbolResolver(Protocol):
    # Whether this backend can decide a claim about a named constant. A backend
    # that cannot must say so, so the verifier can skip rather than report a
    # miss it has no standing to report.
    resolves_constants: bool

    def find(self, repo: Repo, name: str) -> list[Location]:
        """Locations where ``name`` is *declared*. Empty when not found."""
        ...

    def languages(self) -> set[str]:
        """File extensions this resolver can speak, without the dot."""
        ...


# {extension: [pattern templates]}. "{n}" is replaced with the escaped symbol.
_DECLARATIONS: dict[str, list[str]] = {
    # The line must begin with a letter: a C definition starts at column zero
    # with its return type, while an indented "Curl_hash_init(&h, 7);" is a
    # call. Without the anchor every call at statement start read as a
    # declaration and silently verified claims that nothing declares.
    "c": [r"^[A-Za-z_][\w\s\*]*?\b{n}\s*\(", r"^\s*#\s*define\s+{n}\b"],
    "py": [r"^\s*(?:async\s+)?def\s+{n}\s*\(", r"^\s*class\s+{n}\b"],
    "js": [
        r"\bfunction\s*\*?\s*{n}\s*\(",
        r"\bclass\s+{n}\b",
        r"\b{n}\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)",
        r"^\s*(?:async\s+)?{n}\s*\([^)]*\)\s*\{{",
    ],
    "go": [r"^\s*func\s+(?:\([^)]*\)\s*)?{n}\s*\(", r"^\s*type\s+{n}\b"],
    "rs": [r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{n}\b",
           r"^\s*(?:pub\s+)?(?:struct|enum|trait)\s+{n}\b"],
    "java": [r"\b(?:class|interface|enum)\s+{n}\b", r"\b{n}\s*\([^)]*\)\s*(?:throws[^{{]*)?\{{"],
    "rb": [r"^\s*def\s+(?:self\.)?{n}\b", r"^\s*(?:class|module)\s+{n}\b"],
    "php": [r"\bfunction\s+{n}\s*\(", r"\bclass\s+{n}\b"],
}

# Extensions that share a dialect with a primary language above.
_ALIASES = {
    "h": "c", "cc": "c", "cpp": "c", "cxx": "c", "hpp": "c", "m": "c",
    "pyi": "py",
    "mjs": "js", "cjs": "js", "ts": "js", "tsx": "js", "jsx": "js",
    "kt": "java", "scala": "java", "cs": "java",
}


def _dialect(ext: str) -> str | None:
    ext = ext.lower()
    if ext in _DECLARATIONS:
        return ext
    return _ALIASES.get(ext)


_C_LIKE = frozenset({"c", "js", "go", "rs", "java", "php"})

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_C = re.compile(r"//[^\n]*")
_LINE_COMMENT_HASH = re.compile(r"#[^\n]*")

# A symbol preceded by one of these on the same line is being *called* or
# tested, not declared. Without this, "return realloc(ptr, size);" reads as a
# declaration of realloc.
_STATEMENT_KEYWORDS = frozenset(
    {"return", "if", "while", "for", "switch", "sizeof", "else", "case", "do",
     "goto", "and", "or", "not", "in", "assert", "yield", "await", "elif"}
)


def _strip_comments(content: str, dialect: str) -> str:
    """Blank out comments, preserving offsets so reported line numbers stay true.

    Measured on curl, comments were the single largest source of false
    verifications: "* memory released by realloc() before" was being read as a
    declaration of realloc. A claim must never be substantiated by prose that
    merely mentions it -- including prose inside the code itself.
    """
    def blank(match: re.Match) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    if dialect in _C_LIKE:
        content = _BLOCK_COMMENT.sub(blank, content)
        content = _LINE_COMMENT_C.sub(blank, content)
    elif dialect in ("py", "rb"):
        content = _LINE_COMMENT_HASH.sub(blank, content)
    return content


def _preceded_by_keyword(content: str, start: int) -> bool:
    line_start = content.rfind("\n", 0, start) + 1
    before = content[line_start:start].rstrip()
    if not before:
        return False
    if before.endswith(("=", ",", "(", "&", "!", "+", "-", "?", ":", "|")):
        return True
    token = re.split(r"[^A-Za-z_]", before)[-1]
    return token in _STATEMENT_KEYWORDS


class RegexSymbolResolver:
    """Dependency-free declaration matching. Conservative by construction:
    it prefers missing a real declaration to inventing one."""

    # An enum constant is neither a column-zero function definition nor a
    # #define, and the macro form real projects use -- CURLOPT(CURLOPT_URL, ..)
    # -- is indistinguishable by pattern from a call site passing the same name
    # as an argument. Matching it would substantiate fabricated claims, so this
    # backend declines the question instead. A #define still resolves normally.
    resolves_constants = False

    def languages(self) -> set[str]:
        return set(_DECLARATIONS) | set(_ALIASES)

    def find(self, repo: Repo, name: str) -> list[Location]:
        base = re.split(r"::|->|\.", name)[-1]
        if not base:
            return []
        compiled: dict[str, list[re.Pattern]] = {}
        hits: list[Location] = []
        # One grep, then read only the files that could possibly match. Walking
        # the whole tree here is what made this unusable on a real repository.
        for path in repo.grep_files(base):
            ext = path.rsplit(".", 1)[-1] if "." in path else ""
            dialect = _dialect(ext)
            if dialect is None:
                continue
            if dialect not in compiled:
                compiled[dialect] = [
                    re.compile(p.format(n=re.escape(base)), re.MULTILINE)
                    for p in _DECLARATIONS[dialect]
                ]
            raw = repo.read(path)
            if not raw:
                continue
            content = _strip_comments(raw, dialect)
            location = self._first_declaration(content, compiled[dialect], base, path)
            if location is not None:
                hits.append(location)
        return hits

    @staticmethod
    def _first_declaration(content, patterns, base, path) -> Location | None:
        for pattern in patterns:
            for m in pattern.finditer(content):
                # The patterns embed the literal name, so its offset inside the
                # match locates the symbol itself rather than the type in front
                # of it -- which is what the call-site check needs.
                offset = m.group(0).find(base)
                symbol_at = m.start() + (offset if offset >= 0 else 0)
                if _preceded_by_keyword(content, symbol_at):
                    continue
                return Location(path, content.count("\n", 0, m.start()) + 1)
        return None

    def near_misses(self, repo: Repo, name: str, limit: int = 3) -> list[str]:
        """Declared symbols that differ only by case or are a superstring --
        the usual shape of a genuine report citing a renamed function.

        Candidates must be *declarations*, found the same way ``find`` finds
        them. An earlier version matched any identifier before a parenthesis,
        which picked up call sites and string literals and could return the
        queried symbol itself: a report was told its symbol was undeclared and,
        in the same breath, that the closest declared symbol was that symbol. A
        hint that contradicts its own verdict is worse than no hint.
        """
        base = re.split(r"::|->|\.", name)[-1]
        if len(base) < 4:
            return []
        base_low = base.lower()
        found: set[str] = set()
        for path in repo.grep_files(base, ignore_case=True):
            ext = path.rsplit(".", 1)[-1] if "." in path else ""
            dialect = _dialect(ext)
            if dialect is None:
                continue
            raw = repo.read(path)
            if not raw:
                continue
            for declared in self._declared_names(_strip_comments(raw, dialect), dialect):
                low = declared.lower()
                if low == base_low and declared != base:
                    found.add(declared)  # differs only by case
                elif base_low in low and low != base_low and abs(len(low) - len(base_low)) <= 8:
                    found.add(declared)  # renamed by prefix or suffix
                if len(found) >= limit:
                    return sorted(found)
        return sorted(found)

    @staticmethod
    def _declared_names(content: str, dialect: str) -> set[str]:
        """Every symbol declared in ``content``, using the same patterns as
        ``find`` with the name slot opened up to a capture group."""
        names: set[str] = set()
        for template in _DECLARATIONS[dialect]:
            pattern = re.compile(
                template.format(n=r"(?P<sym>[A-Za-z_][A-Za-z0-9_]*)"), re.MULTILINE
            )
            for m in pattern.finditer(content):
                names.add(m.group("sym"))
        return names


DEFAULT_RESOLVER = RegexSymbolResolver()
