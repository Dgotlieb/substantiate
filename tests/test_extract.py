"""Extraction is held to precision over recall.

A claim we fail to extract is a check that does not run. A claim we invent is a
finding against a contributor who never made it. These tests exist mostly to
pin down the second kind.
"""

from __future__ import annotations

import unittest

from tests import fixture

from substantiate.claims import ClaimKind
from substantiate.extract import extract


def kinds(text: str, kind: ClaimKind) -> list[str]:
    return [c.raw for c in extract(text) if c.kind is kind]


def values(text: str, kind: ClaimKind, field: str) -> list:
    return [c.data[field] for c in extract(text) if c.kind is kind]


class TestPrecision(unittest.TestCase):
    def test_english_words_before_parens_are_not_symbols(self):
        text = "The parser (see below) fails when the length (in bytes) is zero."
        self.assertEqual(kinds(text, ClaimKind.SYMBOL), [])

    def test_control_flow_keywords_are_not_symbols(self):
        text = "The code does if (len > 0) and then while (more) inside for (i=0;;)."
        self.assertEqual(kinds(text, ClaimKind.SYMBOL), [])

    def test_urls_do_not_yield_paths_or_versions(self):
        text = "See https://example.com/docs/v1.2.3/setup.py for details."
        claims = extract(text)
        self.assertEqual([c.kind for c in claims], [ClaimKind.URL])

    def test_hex_words_without_digits_are_not_commits(self):
        # "deadbeef" and "accede" are valid hex but are almost always prose.
        text = "The deadbeef value and the accede path are unrelated."
        self.assertEqual(kinds(text, ClaimKind.COMMIT), [])

    def test_line_reference_is_one_claim_not_two(self):
        claims = extract("The check at lib/http2.c:1102 is wrong.")
        self.assertEqual(len(claims), 1)
        self.assertIs(claims[0].kind, ClaimKind.LINE_REF)
        self.assertEqual(claims[0].data, {"path": "lib/http2.c", "line": 1102})

    def test_repeated_claim_counted_once(self):
        text = "Curl_hpack_decode() is broken. Again, Curl_hpack_decode() is broken."
        self.assertEqual(len(kinds(text, ClaimKind.SYMBOL)), 1)


class TestRealWorldFalsePositives(unittest.TestCase):
    """Regressions taken from a run over curl's own documentation.

    That corpus is maintainer-written and accurate, so every claim these
    patterns produced was a false finding against an honest document. The first
    run marked 54.9% of tier-1 claims as not found; each case below is one of
    the culprits.
    """

    def test_products_and_protocols_are_not_symbols(self):
        text = (
            "Built against OpenSSL (or LibreSSL), using Schannel (on Windows), "
            "with NTLM (deprecated) and Negotiate (SPNEGO) over TLS (1.3)."
        )
        self.assertEqual(kinds(text, ClaimKind.SYMBOL), [])

    def test_capitalised_nouns_are_not_symbols(self):
        text = "Signatures (detached) and URLs (absolute) and a Boolean (true)."
        self.assertEqual(kinds(text, ClaimKind.SYMBOL), [])

    def test_illustrative_bare_filenames_are_not_paths(self):
        text = "Write the jar to cookies.txt, read file.txt, or run node.js here."
        self.assertEqual(kinds(text, ClaimKind.PATH), [])

    def test_schemeless_urls_are_not_paths(self):
        text = "Run curl example.com/moo2.txt and server.example.com/share/file.txt now."
        self.assertEqual(kinds(text, ClaimKind.PATH), [])

    def test_dotfile_directories_are_still_paths(self):
        self.assertEqual(
            kinds("See .github/workflows/ci.yml for the matrix.", ClaimKind.PATH),
            [".github/workflows/ci.yml"],
        )

    def test_dates_are_not_commit_shas(self):
        self.assertEqual(kinds("Released on 20190808 as planned.", ClaimKind.COMMIT), [])

    def test_a_real_call_still_extracts(self):
        # The precision rules must not silence the thing the tool is for.
        text = "Fix Curl_hpack_decode() and curl_easy_setopt(CURLOPT_URL, url)."
        self.assertEqual(
            sorted(values(text, ClaimKind.SYMBOL, "name")),
            ["Curl_hpack_decode", "curl_easy_setopt"],
        )

    def test_a_real_path_still_extracts(self):
        self.assertEqual(kinds("See lib/vtls/openssl.c for details.", ClaimKind.PATH),
                         ["lib/vtls/openssl.c"])


class TestRecall(unittest.TestCase):
    def test_underscored_and_camel_symbols(self):
        text = "Both Curl_hpack_decode() and parseHeaderBlock() are involved."
        self.assertEqual(
            sorted(values(text, ClaimKind.SYMBOL, "name")),
            ["Curl_hpack_decode", "parseHeaderBlock"],
        )

    def test_version_range_yields_both_endpoints(self):
        text = "This affects versions 8.9.0 through 8.12.1."
        self.assertEqual(values(text, ClaimKind.VERSION, "version"), ["8.9.0", "8.12.1"])

    def test_prose_line_reference(self):
        claims = extract("The bug is on line 42 of lib/http2.c today.")
        self.assertEqual(claims[0].data, {"path": "lib/http2.c", "line": 42})

    def test_rfc_with_section(self):
        claims = extract("See RFC 9113 section 6.5.2 for the semantics.")
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0].data, {"number": 9113, "section": "6.5.2"})

    def test_identifiers(self):
        text = "Assigned CVE-2026-41022, which is CWE-122."
        self.assertEqual(values(text, ClaimKind.CVE, "id"), ["CVE-2026-41022"])
        self.assertEqual(values(text, ClaimKind.CWE, "number"), [122])


class TestCodeBlocks(unittest.TestCase):
    def test_claims_inside_fences_are_marked(self):
        text = "Prose lib/a.c here.\n\n```\ncrash in lib/b.c\n```\n"
        marks = {c.data.get("path"): c.in_code for c in extract(text)}
        self.assertFalse(marks["lib/a.c"])
        self.assertTrue(marks["lib/b.c"])


class TestFixtures(unittest.TestCase):
    def test_fabricated_report_surfaces_its_claims(self):
        text = fixture("fabricated_hpack.md")
        self.assertIn("src/http2/hpack.c", values(text, ClaimKind.PATH, "path"))
        self.assertIn("Curl_hpack_decode", values(text, ClaimKind.SYMBOL, "name"))
        self.assertIn("CVE-2026-41022", values(text, ClaimKind.CVE, "id"))
        self.assertEqual(values(text, ClaimKind.VERSION, "version"), ["8.9.0", "8.12.1"])

    def test_genuine_report_surfaces_its_claims(self):
        text = fixture("genuine_http2.md")
        symbols = values(text, ClaimKind.SYMBOL, "name")
        self.assertIn("Curl_http2_done", symbols)
        self.assertIn("Curl_http2_setup", symbols)
        self.assertIn("lib/http2.c", values(text, ClaimKind.PATH, "path"))


if __name__ == "__main__":
    unittest.main()
