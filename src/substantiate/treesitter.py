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


# Parsed declarations, keyed by (repository, revision, path). A resolver is
# built per check, so this outlives the instance deliberately.
_DECLARATION_CACHE: dict[tuple[str, str, str], list[tuple[str, int]]] = {}
_CACHE_LIMIT = 4096


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


# --- Enum bodies -----------------------------------------------------------
#
# The C grammar has no rule for a macro-wrapped enumerator. Faced with
# "CURLOPT(CURLOPT_AUTOREFERER, CURLOPTTYPE_LONG, 58)" inside an enumerator
# list it error-recovers, and where the recovered ERROR node ends is arbitrary:
# for one entry it stops after "CURLOPT(" and the name survives as a real
# enumerator, for the next it swallows "CURLOPT(CURLOPT_AUTOREFERER" whole and
# the name is never seen. Two entries with identical syntax, 22 lines apart in
# one enum, got opposite answers -- which reads as the tool being broken rather
# than the claim being wrong.
#
# Worse in the other direction: recovery promoted "CURLOPTTYPE_LONG", a macro
# *argument* that nothing declares, to an enumerator. A fabricated claim naming
# it was confirmed by a tool whose whole purpose is to catch that.
#
# So enum bodies are read from their own text rather than off the recovered
# tree. Inside an enum body the grammar is small enough to scan directly, and
# an identifier in entry position is a declaration by construction -- which is
# what keeps this from becoming "any identifier near a broken parse counts".

_IDENT = re.compile(r"[A-Za-z_]\w*")
_DEFINE_NAME = re.compile(r"#\s*define\s+([A-Za-z_]\w*)")
_DEFINE_FN = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)\(([^)]*)\)[ \t]*(.*)$", re.MULTILINE
)

# "##" is the standard paste operator; "/**/" is what projects wrote before
# C99, and curl still carries both spellings of CINIT in the same header --
# under #ifdef, so whichever this reads must give the same answer.
_PASTE = r"(?:##|/\*\*/)"
_PASTE_BEFORE = r"([A-Za-z_]\w*)\s*" + _PASTE + r"\s*$"
_PASTE_AFTER = r"\s*" + _PASTE + r"\s*([A-Za-z_]\w*)"


def _mask(text: str) -> str:
    """Blank comments and literals, preserving length so offsets still map to lines."""
    out = list(text)
    i, n = 0, len(text)

    def blank(lo: int, hi: int) -> None:
        for k in range(lo, min(hi, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        two = text[i:i + 2]
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text[i] in "\"'":
            quote, j = text[i], i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
        else:
            i += 1
    return "".join(out)


def _take_preproc(masked: str):
    """Blank preprocessor lines, returning the text and the names they define.

    curl interleaves "#define CURLOPT_PROGRESSDATA CURLOPT_XFERINFODATA" into
    the middle of the option enum. Those are real declarations, and leaving the
    directive in place would also derail the comma splitting below.
    """
    out = list(masked)
    defines: list[tuple[str, int]] = []
    pos = 0
    continuing = False
    for line in masked.split("\n"):
        stripped = line.lstrip()
        if continuing or stripped.startswith("#"):
            if not continuing:
                found = _DEFINE_NAME.match(line, len(line) - len(stripped))
                if found:
                    defines.append((found.group(1), pos + found.start(1)))
            for k in range(pos, pos + len(line)):
                out[k] = " "
            continuing = line.rstrip().endswith("\\")
        pos += len(line) + 1
    return "".join(out), defines


def _split_on_commas(text: str):
    """Yield (offset, chunk) for each comma-separated entry at bracket depth zero."""
    depth = start = 0
    for i, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth <= 0:
            yield start, text[start:i]
            start = i + 1
    yield start, text[start:]


def _call_arguments(text: str, paren: int):
    """Yield (argument, offset) for the call whose opening paren is at ``paren``."""
    args: list[tuple[str, int]] = []
    depth, start = 0, paren + 1
    for i in range(paren, len(text)):
        char = text[i]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                args.append((text[start:i], start))
                break
        elif char == "," and depth == 1:
            args.append((text[start:i], start))
            start = i + 1
    return args


def _enumerator_macros(source: str) -> dict[str, tuple[int, str, str]]:
    """{macro: (argument index, prefix, suffix)} for defines that name an enumerator.

    Through curl 7.62 every option was declared as::

        #define CINIT(na, t, nu) CURLOPT_ ## na = t + nu
        CINIT(SSL_VERIFYPEER, LONG, 64),

    so "CURLOPT_SSL_VERIFYPEER" appears zero times in the header that declares
    it -- the preprocessor pastes it together. Reading the define tells us which
    argument carries the name and what gets pasted onto it.
    """
    macros: dict[str, tuple[int, str, str]] = {}
    for match in _DEFINE_FN.finditer(source):
        name, params, body = match.group(1), match.group(2), match.group(3)
        names = [p.strip() for p in params.split(",") if p.strip()]
        if not names:
            continue
        # Only the part before "=" names the enumerator; the rest is its value.
        head = body.split("=", 1)[0]
        for token in _IDENT.finditer(head):
            if token.group(0) not in names:
                continue
            before = re.search(_PASTE_BEFORE, head[:token.start()])
            after = re.match(_PASTE_AFTER, head[token.end():])
            macros[name] = (
                names.index(token.group(0)),
                before.group(1) if before else "",
                after.group(1) if after else "",
            )
            break
    return macros


def _entry_declaration(entry: str, offset: int, macros: dict[str, tuple[int, str, str]]):
    """The (name, offset) an enum entry declares, or None if it declares nothing."""
    lead = _IDENT.search(entry)
    if lead is None:
        return None
    tail = entry[lead.end():]
    indent = len(tail) - len(tail.lstrip())
    if tail[indent:indent + 1] != "(":
        # A plain enumerator: "CURLOPT_URL = 2".
        return lead.group(0), offset + lead.start()

    # A macro-wrapped one. Where the name sits is whatever the define said, and
    # argument zero for a macro this file does not define -- the shape every
    # project using this idiom writes, and the only guess with a basis.
    index, prefix, suffix = macros.get(lead.group(0), (0, "", ""))
    args = _call_arguments(entry, lead.end() + indent)
    if index >= len(args):
        return None
    text, position = args[index]
    named = _IDENT.search(text)
    if named is None:
        return None
    return prefix + named.group(0) + suffix, offset + position + named.start()


def _enum_declarations(node, macros: dict[str, tuple[int, str, str]]):
    """Yield (name, line) for each entry of an enumerator list, from its text."""
    text = node.text.decode("utf-8", "replace")
    opened = text.find("{")
    if opened < 0:
        return
    closed = text.rfind("}")
    start = opened + 1
    body = text[start:closed if closed > opened else len(text)]
    body, defines = _take_preproc(_mask(body))
    base = node.start_point[0]

    def line_of(within: int) -> int:
        return base + text.count("\n", 0, start + within) + 1

    for name, position in defines:
        yield name, line_of(position)
    for offset, entry in _split_on_commas(body):
        declared = _entry_declaration(entry, offset, macros)
        if declared is not None:
            yield declared[0], line_of(declared[1])


# Where a pasted enum constant is declared. The idiom exists to write a public
# option list, so it lives in a header essentially by definition.
_HEADER_EXTENSIONS = frozenset({"h", "hpp", "hxx", "hh", "inc"})
_PASTE_FILE_LIMIT = 80


def _is_header(path: str) -> bool:
    return path.rsplit(".", 1)[-1].lower() in _HEADER_EXTENSIONS if "." in path else False


def _paste_fragments(name: str):
    """Fragments of ``name`` worth grepping when the whole of it appears nowhere.

    A pasted name is its parts joined by underscores, and the part the macro
    actually receives is what the source spells. Dropping up to two leading or
    trailing parts covers a prefix paste ("CURLOPT_ ## na"), a suffix paste
    ("na ## _OPT") and one of each. Short fragments are skipped: grepping a repo
    for "SSL" costs a great deal and narrows nothing.
    """
    # Pasting an identifier together is an enum and constant idiom, and those
    # names are shouty. Restricting to them is not just tidiness: every fragment
    # is another grep of the whole repository, paid on the miss path, and
    # "allocate_fake_connection_struct" was never going to be assembled by the
    # preprocessor.
    if name != name.upper():
        return
    parts = name.split("_")
    if len(parts) < 2:
        return
    seen = set()
    for lead, trail in ((1, 0), (0, 1), (2, 0), (0, 2), (1, 1)):
        if lead + trail >= len(parts):
            continue
        fragment = "_".join(parts[lead:len(parts) - trail])
        if len(fragment) >= 4 and fragment not in seen:
            seen.add(fragment)
            yield fragment


def _walk_declarations(root, language: str):
    """Yield (name, line) for every declaration in the tree."""
    declaring = _DECLARING_NODES.get(language, frozenset())
    macros = None
    if language in ("c", "cpp"):
        try:
            macros = _enumerator_macros(root.text.decode("utf-8", "replace"))
        except (AttributeError, UnicodeDecodeError):
            macros = {}
    stack = [root]
    while stack:
        node = stack.pop()
        if macros is not None and node.type == "enumerator_list":
            # Read the body rather than descending into it: the "enumerator"
            # nodes under here are whatever error recovery happened to salvage.
            yield from _enum_declarations(node, macros)
            continue
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
        # One report asks about many symbols and they cluster in the same few
        # files, so the same header was being reparsed for every claim. The key
        # is the revision, not the path: a benchmark walking a project's whole
        # tag history must not be handed another tag's answers.
        key = (str(repo.path), repo.ref, path)
        cached = _DECLARATION_CACHE.get(key)
        if cached is not None:
            return cached
        content = repo.read(path)
        if not content:
            return None
        try:
            tree = _parser(language).parse(content.encode("utf-8", "replace"))
        except Exception:
            return None
        declarations = list(_walk_declarations(tree.root_node, language))
        if len(_DECLARATION_CACHE) >= _CACHE_LIMIT:
            _DECLARATION_CACHE.clear()
        _DECLARATION_CACHE[key] = declarations
        return declarations

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
        return hits or self._find_pasted(repo, base)

    def _find_pasted(self, repo: Repo, base: str) -> list[Location]:
        """Look for a name the preprocessor assembles, which no file contains.

        Candidate files are chosen by grepping for the name, which works right
        up until the name does not exist as text. Through curl 7.62 every
        option was written ``CINIT(SSL_VERIFYPEER, LONG, 64)`` and pasted onto
        a prefix, so grepping "CURLOPT_SSL_VERIFYPEER" offers the docs and
        examples that mention it and never the header that declares it.

        So the fragments are grepped instead, to widen the candidate set only.
        What counts as a declaration is still decided by the parser, and only
        an entry whose reconstructed name matches the query exactly is a hit --
        a fragment appearing somewhere proves nothing on its own.

        Only headers are considered, and only while a fragment still narrows
        something. A fragment is necessarily vaguer than the name it came from:
        "CURLOPT" matches 980 files in curl but 19 of its headers, and parsing
        the other 961 to find an enum that was never going to be in them made a
        fabricated option the slowest thing the tool could be asked about.
        """
        for fragment in _paste_fragments(base):
            hits: list[Location] = []
            candidates = [p for p in repo.grep_files(fragment) if _is_header(p)]
            if len(candidates) > _PASTE_FILE_LIMIT:
                continue
            for path in candidates:
                decls = self._declarations(repo, path)
                if decls is None:
                    continue
                for declared, line in decls:
                    if declared == base:
                        hits.append(Location(path, line))
                        break
            if hits:
                return hits
        return []

    def declares_namespace(self, repo: Repo, prefix: str) -> bool:
        for path in repo.grep_files(prefix):
            decls = self._declarations(repo, path)
            if decls is None:
                if self.fallback.declares_namespace_in(repo, prefix, path):
                    return True
                continue
            for declared, _line in decls:
                if declared.startswith(prefix):
                    return True
        return False

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
