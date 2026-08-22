"""Symbol resolution.

A report saying ``Curl_hpack_decode()`` is claiming a *declaration* exists, not
that a string appears somewhere. Matching the bare name would let a mention in a
comment -- or in the report's own quoted diff -- corroborate itself, which is
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
    def find(self, repo: Repo, name: str) -> list[Location]:
        """Locations where ``name`` is *declared*. Empty when not found."""
        ...

    def languages(self) -> set[str]:
        """File extensions this resolver can speak, without the dot."""
        ...


# {extension: [pattern templates]}. "{n}" is replaced with the escaped symbol.
_DECLARATIONS: dict[str, list[str]] = {
    "c": [r"^[\w\s\*]*?\b{n}\s*\(", r"^\s*#\s*define\s+{n}\b"],
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


class RegexSymbolResolver:
    """Dependency-free declaration matching. Conservative by construction:
    it prefers missing a real declaration to inventing one."""

    def languages(self) -> set[str]:
        return set(_DECLARATIONS) | set(_ALIASES)

    def find(self, repo: Repo, name: str) -> list[Location]:
        base = re.split(r"::|->|\.", name)[-1]
        if not base:
            return []
        hits: list[Location] = []
        for path in repo.files:
            ext = path.rsplit(".", 1)[-1] if "." in path else ""
            dialect = _dialect(ext)
            if dialect is None:
                continue
            patterns = [
                re.compile(p.format(n=re.escape(base)), re.MULTILINE)
                for p in _DECLARATIONS[dialect]
            ]
            content = repo.read(path)
            if not content or base not in content:
                continue  # cheap reject before running the real patterns
            for pattern in patterns:
                for m in pattern.finditer(content):
                    line = content.count("\n", 0, m.start()) + 1
                    hits.append(Location(path, line))
                    break
        return hits

    def near_misses(self, repo: Repo, name: str, limit: int = 3) -> list[str]:
        """Declared symbols that differ only by case or are a superstring --
        the usual shape of a genuine report citing a renamed function."""
        base = re.split(r"::|->|\.", name)[-1].lower()
        if len(base) < 4:
            return []
        found: set[str] = set()
        ident = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(")
        for path in repo.files:
            ext = path.rsplit(".", 1)[-1] if "." in path else ""
            if _dialect(ext) is None:
                continue
            content = repo.read(path)
            if not content:
                continue
            for m in ident.finditer(content):
                cand = m.group(1)
                low = cand.lower()
                if low == base and cand != base:
                    found.add(cand)
                elif base in low and low != base and abs(len(low) - len(base)) <= 8:
                    found.add(cand)
                if len(found) >= limit:
                    return sorted(found)
        return sorted(found)


DEFAULT_RESOLVER = RegexSymbolResolver()
