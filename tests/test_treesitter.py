"""Tree-sitter backend.

Skipped entirely when the optional extra is not installed, so the
zero-dependency path stays the one CI proves by default. The parity tests
matter most: the two backends must agree on ordinary declarations, or swapping
resolvers would silently change verdicts.
"""

from __future__ import annotations

import shutil
import unittest

from tests import fake_repo, fixture

from substantiate.repo import Repo
from substantiate.symbols import DEFAULT_RESOLVER
from substantiate.treesitter import available
from substantiate.verdict import Status
from substantiate.verify import check


@unittest.skipUnless(available(), "substantiate[treesitter] not installed")
class TreeSitterCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from substantiate.treesitter import TreeSitterSymbolResolver

        cls.root = fake_repo.build()
        cls.repo = Repo(cls.root, "HEAD")
        cls.ts = TreeSitterSymbolResolver()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)


class TestParity(TreeSitterCase):
    def test_both_backends_find_the_same_c_functions(self):
        for symbol in ("Curl_http2_setup", "Curl_http2_done", "Curl_hpack_cleanup"):
            with self.subTest(symbol=symbol):
                regex = {loc.path for loc in DEFAULT_RESOLVER.find(self.repo, symbol)}
                tree = {loc.path for loc in self.ts.find(self.repo, symbol)}
                self.assertTrue(tree, f"tree-sitter found no declaration of {symbol}")
                self.assertEqual(regex, tree)

    def test_both_backends_reject_the_same_undeclared_symbol(self):
        self.assertEqual(DEFAULT_RESOLVER.find(self.repo, "Curl_hpack_decode"), [])
        self.assertEqual(self.ts.find(self.repo, "Curl_hpack_decode"), [])

    def test_genuine_report_stays_clean_under_tree_sitter(self):
        result = check(fixture("genuine_http2.md"), self.repo, resolver=self.ts)
        self.assertEqual(
            [v.claim.raw for v in result.by_status(Status.NOT_FOUND)],
            [],
        )


class TestMacroWrappedEnumerators(TreeSitterCase):
    """Enum constants a C project declares through a macro.

    The C grammar has no rule for ``FIXTURE_OPT(NAME, TYPE, 68)`` in an
    enumerator list, so it error-recovers -- and the recovery boundary is
    arbitrary. Against curl, ``CURLOPT_AUTOREFERER`` and
    ``CURLOPT_SSL_VERIFYPEER`` sit 22 lines apart in one enum with identical
    syntax, and only one of them resolved. Reading declarations off the
    recovered tree is what made the answer depend on the neighbours.
    """

    def declared(self, name):
        return [str(loc) for loc in self.ts.find(self.repo, name)]

    def test_entry_after_an_interleaved_define_resolves(self):
        # The regression from issue #4: a #define inside the enum body shifts
        # where error recovery ends, and the next entry's name was swallowed.
        self.assertTrue(
            self.declared("FIXTURE_OPT_AUTOREFERER"),
            "an option declared one line after an interleaved #define",
        )

    def test_entry_whose_macro_call_spans_two_lines_resolves(self):
        self.assertTrue(self.declared("FIXTURE_OPT_KRBLEVEL"))

    def test_neighbouring_entries_agree(self):
        # The symptom that reads as the tool being broken: identical syntax in
        # one enum, opposite answers.
        for name in (
            "FIXTURE_OPT_MAXCONNECTS",
            "FIXTURE_OPT_XFERINFODATA",
            "FIXTURE_OPT_AUTOREFERER",
            "FIXTURE_OPT_KRBLEVEL",
        ):
            with self.subTest(symbol=name):
                self.assertTrue(self.declared(name))

    def test_a_pasted_name_resolves_where_the_source_never_spells_it(self):
        # Issue #3. "FIXTURE_OPT_TOKENPASTED" appears nowhere in options.h; the
        # preprocessor builds it from "FIXTURE_OPT_ ## na". Through curl 7.62
        # this was every CURLOPT_* name in the project.
        self.assertTrue(self.declared("FIXTURE_OPT_TOKENPASTED"))

    def test_the_declaring_file_is_reached_without_containing_the_name(self):
        # The half of issue #3 the parser alone could not fix. Candidate files
        # are chosen by grepping for the name, so a pasted name offered the docs
        # that mention it and never the header that declares it.
        from substantiate.repo import Repo  # noqa: F401

        self.assertEqual(self.repo.grep_files("FIXTURE_OPT_TOKENPASTED"), [])
        self.assertTrue(self.declared("FIXTURE_OPT_TOKENPASTED"))

    def test_widening_the_search_does_not_manufacture_declarations(self):
        # Grepping fragments widens which files are looked at, nothing else.
        # A name that shares a fragment with a real option but is not declared
        # must stay not-found, or the fix for issue #3 would have quietly
        # turned every miss into a pass.
        for name in ("FIXTURE_OPT_NOTREAL", "FIXTURE_OPT_LONG",
                     "FIXTURE_INIT_TOKENPASTED"):
            with self.subTest(symbol=name):
                self.assertEqual(self.declared(name), [])

    def test_a_fabricated_option_is_still_not_found(self):
        # Recovering names from a broken parse must not become blanket amnesty.
        self.assertEqual(self.declared("FIXTURE_OPT_INVENTED"), [])

    def test_macro_arguments_are_not_declarations(self):
        # The dangerous direction. FIXTURE_TYPE_LONG is passed as the type
        # argument of several entries and declared by nothing; error recovery
        # promoted it to an enumerator, so a fabricated claim naming it was
        # confirmed by a tool whose entire purpose is to catch that.
        for name in ("FIXTURE_TYPE_LONG", "FIXTURE_TYPE_CBPOINT",
                     "FIXTURE_TYPE_STRINGPOINT"):
            with self.subTest(symbol=name):
                self.assertEqual(self.declared(name), [])

    def test_the_macro_itself_is_still_declared(self):
        # It is a real #define, and the regex backend agrees.
        self.assertTrue(self.declared("FIXTURE_OPT"))


class TestNearMisses(TreeSitterCase):
    def test_near_miss_never_returns_the_queried_symbol(self):
        # The regression that shipped to a real issue comment: a symbol was
        # reported undeclared while the hint named that same symbol as declared.
        for resolver in (DEFAULT_RESOLVER, self.ts):
            with self.subTest(resolver=type(resolver).__name__):
                misses = resolver.near_misses(self.repo, "Curl_hpack_decode")
                self.assertNotIn("Curl_hpack_decode", misses)

    def test_near_miss_finds_the_renamed_neighbour(self):
        for resolver in (DEFAULT_RESOLVER, self.ts):
            with self.subTest(resolver=type(resolver).__name__):
                self.assertIn(
                    "Curl_hpack_decode_header",
                    resolver.near_misses(self.repo, "Curl_hpack_decode"),
                )

    def test_call_sites_are_not_offered_as_declarations(self):
        # "Curl_hpack_decode(" appears in this repository's own test fixtures
        # as a string literal. A hint must never be sourced from one.
        misses = self.ts.near_misses(self.repo, "Curl_http2_setu")
        for name in misses:
            self.assertTrue(self.ts.find(self.repo, name), f"{name} is not declared")


@unittest.skipUnless(available(), "substantiate[treesitter] not installed")
class TestEnumBodyScanning(unittest.TestCase):
    """The enum scanner itself, on source too small to need a repository.

    Reading enum bodies as text rather than off the parse tree buys consistency
    at the cost of having to get the small grammar right by hand -- so the
    shapes that would break it quietly are pinned here.
    """

    def declared(self, source, language="c"):
        from tree_sitter_language_pack import get_parser

        from substantiate.treesitter import _walk_declarations

        tree = get_parser(language).parse(source.encode())
        return sorted({name for name, _ in _walk_declarations(tree.root_node, language)})

    def test_plain_enum(self):
        self.assertEqual(
            self.declared("enum colour { RED, GREEN = 2, BLUE };"),
            ["BLUE", "GREEN", "RED", "colour"],
        )

    def test_commas_inside_a_value_expression_do_not_split_entries(self):
        # "A = MK(1, 2)" is one entry containing two commas.
        self.assertEqual(
            self.declared("#define MK(a, b) ((a) + (b))\nenum e { A = MK(1, 2), B };"),
            ["A", "B", "MK", "e"],
        )

    def test_commas_and_braces_in_comments_and_strings_are_ignored(self):
        self.assertEqual(
            self.declared('enum e {\n /* }, and , here */\n X = SZ("a,b}c"), Y\n};'),
            ["X", "Y", "e"],
        )

    def test_the_name_argument_need_not_be_the_first(self):
        # Guessing argument zero would declare the type token instead, which is
        # the false positive this whole path exists to avoid.
        self.assertEqual(
            self.declared(
                "#define ENTRY(t, na, nu) na = ((t) + (nu))\n"
                "enum e { ENTRY(TYPE_LONG, OPT_FIRST, 1) };"
            ),
            ["ENTRY", "OPT_FIRST", "e"],
        )

    def test_a_suffix_paste_is_applied_too(self):
        self.assertEqual(
            self.declared("#define D(na) MY_ ## na ## _OPT = 0\nenum e { D(ALPHA) };"),
            ["D", "MY_ALPHA_OPT", "e"],
        )

    def test_cpp_enum_class(self):
        self.assertEqual(
            self.declared("enum class Level : int { Low = 1, High };", "cpp"),
            ["High", "Level", "Low"],
        )

    def test_a_trailing_comma_declares_nothing_extra(self):
        self.assertEqual(self.declared("enum e { P, Q, };"), ["P", "Q", "e"])


if __name__ == "__main__":
    unittest.main()
