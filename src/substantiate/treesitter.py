"""Tree-sitter symbol resolution.

The regex resolver is honest about what it is: a pattern match over text. It
misses declarations that span lines, it cannot tell a declaration from a string
literal that looks like one, and it has no idea what an enum constant is.

This backend parses instead. It is optional -- ``pip install
substantiate[treesitter]`` -- because tier 1 keeping a zero-dependency install is
worth more than the accuracy for most users, and because a maintainer running
this on untrusted reports should be able to audit what they installed.

Selection is automatic: ``best_resolver()`` returns this when the dependency is
importable and the regex resolver otherwise, so behaviour degrades rather than
breaks. Both satisfy the same ``SymbolResolver`` protocol.
"""

from __future__ import annotations

import re
from functools import lru_cache

from .repo import Repo
from .symbols import DEFAULT_RESOLVER, Location, RegexSymbolResolver

# Extension -> tree-sitter language name.
_LANGUAGES: dict[str, str] = {
    "c": "c", "h": "c",
    "cc": "cpp", "cpp": "cpp", "cxx": "cpp", "hpp": "cpp",
    "py": "python", "pyi": "python",
    "js": "javascript", "mjs": "javascript", "cjs": "javascript", "jsx": "javascript",
    "ts": "typescript", "tsx": "tsx",
    "go": "go",
    "rs": "rust",
    "java": "java",
    "rb": "ruby",
    "php": "php",
}

# Node types that introduce a name, per language. The name is read from the
# "name" field where the grammar provides one; C is handled separately because
# a function's identifier is buried under pointer and array declarators.
_DECLARING_NODES: dict[str, frozenset[str]] = {
    "c": frozenset({
        "function_definition", "declaration", "preproc_def", "preproc_function_def",
        "struct_specifier", "union_specifier", "enum_specifier", "type_definition",
        "enumerator",
    }),
    "cpp": frozenset({
        "function_definition", "declaration", "preproc_def", "preproc_function_def",
        "struct_specifier", "union_specifier", "enum_specifier", "type_definition",
        "enumerator", "class_specifier", "namespace_definition",
    }),
    "python": frozenset({"function_definition", "class_definition"}),
    "javascript": frozenset({
        "function_declaration", "generator_function_declaration", "class_declaration",
        "method_definition", "variable_declarator",
    }),
    "typescript": frozenset({
        "function_declaration", "generator_function_declaration", "class_declaration",
        "method_definition", "variable_declarator", "interface_declaration",
        "type_alias_declaration", "enum_declaration",
    }),
    "go": frozenset({"function_declaration", "method_declaration", "type_spec", "const_spec"}),
    "rust": frozenset({
        "function_item", "struct_item", "enum_item", "trait_item", "const_item",
        "static_item", "type_item", "macro_definition", "mod_item",
    }),
    "java": frozenset({
        "method_declaration", "class_declaration", "interface_declaration",
        "enum_declaration", "constructor_declaration",
    }),
    "ruby": frozenset({"method", "singleton_method", "class", "module"}),
    "php": frozenset({
        "function_definition", "method_declaration", "class_declaration",
        "interface_declaration", "trait_declaration",
    }),
}
_DECLARING_NODES["tsx"] = _DECLARING_NODES["typescript"]

_IDENTIFIERS = frozenset(
    {"identifier", "type_identifier", "field_identifier", "constant",
     "property_identifier", "name", "word"}
)


class TreeSitterUnavailable(RuntimeError):
    pass


@lru_cache(maxsize=None)
def _parser(language: str):
    try:
        from tree_sitter_language_pack import get_parser
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise TreeSitterUnavailable("install substantiate[treesitter]") from exc
    return get_parser(language)


def available() -> bool:
    try:
        _parser("python")
        return True
    except Exception:
        return False


def _declarator_identifier(node):
    """Descend a C declarator chain to the identifier it ultimately names.

    ``static CURLcode *Curl_http2_setup(struct connectdata *conn)`` nests the
    identifier under a pointer_declarator inside a function_declarator; the
    name is only reachable by walking down.
    """
    current = node
    for _ in range(12):  # declarator nesting is shallow; bound it rather than recurse
        if current.type in _IDENTIFIERS:
            return current
        nxt = current.child_by_field_name("declarator") or current.child_by_field_name("name")
        if nxt is None:
            for child in current.children:
                if child.type in _IDENTIFIERS:
                    return child
                if "declarator" in child.type:
                    nxt = child
                    break
        if nxt is None:
            return None
        current = nxt
    return None


def _name_node(node, language: str):
    if language in ("c", "cpp") and node.type in (
        "function_definition", "declaration", "type_definition"
    ):
        return _declarator_identifier(node)
    named = node.child_by_field_name("name")
    if named is not None:
        return named if named.type in _IDENTIFIERS else _declarator_identifier(named)
    return _declarator_identifier(node)


def _walk_declarations(root, language: str):
    """Yield (name, line) for every declaration in the tree."""
    declaring = _DECLARING_NODES.get(language, frozenset())
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in declaring:
            ident = _name_node(node, language)
            if ident is not None:
                try:
                    yield ident.text.decode("utf-8", "replace"), ident.start_point[0] + 1
                except (AttributeError, UnicodeDecodeError):
                    pass
        stack.extend(node.children)


class TreeSitterSymbolResolver:
    """Resolves declarations by parsing, falling back per-file to the regex
    resolver for languages tree-sitter does not cover here."""

    # Enumerators are declarations in the grammar, so both the plain and the
    # macro-wrapped form resolve without guessing from surrounding text.
    resolves_constants = True

    def __init__(self, fallback: RegexSymbolResolver | None = None) -> None:
        self.fallback = fallback or DEFAULT_RESOLVER

    def languages(self) -> set[str]:
        return set(_LANGUAGES) | self.fallback.languages()

    def _declarations(self, repo: Repo, path: str):
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        language = _LANGUAGES.get(ext)
        if language is None:
            return None
        content = repo.read(path)
        if not content:
            return None
        try:
            tree = _parser(language).parse(content.encode("utf-8", "replace"))
        except Exception:
            return None
        return list(_walk_declarations(tree.root_node, language))

    def find(self, repo: Repo, name: str) -> list[Location]:
        base = re.split(r"::|->|\.", name)[-1]
        if not base:
            return []
        hits: list[Location] = []
        for path in repo.grep_files(base):
            decls = self._declarations(repo, path)
            if decls is None:
                # Not a language this backend parses. Its coverage is no longer
                # a superset of the regex resolver's -- that one reads CMake,
                # where a C project declares its build options -- so the file
                # is handed over rather than dropped.
                location = self.fallback.find_in(repo, base, path)
                if location is not None:
                    hits.append(location)
                continue
            for declared, line in decls:
                if declared == base:
                    hits.append(Location(path, line))
                    break
        return hits

    def near_misses(self, repo: Repo, name: str, limit: int = 3) -> list[str]:
        base = re.split(r"::|->|\.", name)[-1]
        if len(base) < 4:
            return []
        base_low = base.lower()
        found: set[str] = set()
        for path in repo.grep_files(base, ignore_case=True):
            decls = self._declarations(repo, path)
            if decls is None:
                continue
            for declared, _ in decls:
                low = declared.lower()
                if low == base_low and declared != base:
                    found.add(declared)
                elif base_low in low and low != base_low and abs(len(low) - len(base_low)) <= 8:
                    found.add(declared)
                if len(found) >= limit:
                    return sorted(found)
        return sorted(found)


def best_resolver():
    """The most accurate resolver this install can provide."""
    return TreeSitterSymbolResolver() if available() else DEFAULT_RESOLVER
