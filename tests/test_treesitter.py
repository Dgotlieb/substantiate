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


if __name__ == "__main__":
    unittest.main()
