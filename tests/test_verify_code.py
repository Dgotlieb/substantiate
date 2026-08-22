"""Tier 1 verification against a real git repository."""

from __future__ import annotations

import shutil
import unittest

from tests import fake_repo, fixture

from corroborate.claims import ClaimKind
from corroborate.repo import Repo
from corroborate.verdict import Status
from corroborate.verify import check


class TierOneCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = fake_repo.build()
        cls.repo = Repo(cls.root, "HEAD")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def verdicts(self, text):
        return {(v.claim.kind, v.claim.raw): v for v in check(text, self.repo).verdicts}


class TestFabricatedReport(TierOneCase):
    def setUp(self):
        self.result = check(fixture("fabricated_hpack.md"), self.repo)
        self.by_raw = {v.claim.raw: v for v in self.result.verdicts}

    def test_nonexistent_path_is_not_found(self):
        v = self.by_raw["src/http2/hpack.c"]
        self.assertIs(v.status, Status.NOT_FOUND)

    def test_moved_file_produces_a_hint(self):
        # The fairness guarantee: a path that fails because the file lives
        # elsewhere must say so, not just report a miss.
        v = self.by_raw["src/http2/hpack.c"]
        self.assertIsNotNone(v.hint)
        self.assertIn("lib/hpack.c", v.hint)

    def test_undeclared_symbol_is_not_found_with_near_miss(self):
        v = self.by_raw["Curl_hpack_decode"]
        self.assertIs(v.status, Status.NOT_FOUND)
        self.assertIsNotNone(v.hint)
        self.assertIn("Curl_hpack_decode_header", v.hint)

    def test_line_beyond_end_of_file_is_not_found(self):
        v = self.by_raw["lib/http2.c:1102"]
        self.assertIs(v.status, Status.NOT_FOUND)
        self.assertIn("lines", v.detail)

    def test_real_line_reference_verifies(self):
        self.assertIs(self.by_raw["lib/http2.c:42"].status, Status.VERIFIED)

    def test_unreleased_version_is_not_found(self):
        self.assertIs(self.by_raw["8.9.0"].status, Status.NOT_FOUND)

    def test_released_version_verifies(self):
        self.assertIs(self.by_raw["8.12.1"].status, Status.VERIFIED)

    def test_tier_two_claims_are_skipped_by_default(self):
        cve = self.by_raw["CVE-2026-41022"]
        self.assertIs(cve.status, Status.SKIPPED)

    def test_overall_shape(self):
        self.assertGreaterEqual(len(self.result.by_status(Status.NOT_FOUND)), 4)


class TestGenuineReport(TierOneCase):
    """The false-positive guard. A report describing real code must come back
    clean, or maintainers will stop trusting the output within a week."""

    def setUp(self):
        self.result = check(fixture("genuine_http2.md"), self.repo)

    def test_nothing_fails_to_resolve(self):
        failures = [
            f"{v.claim.kind.value} {v.claim.raw}: {v.detail}"
            for v in self.result.by_status(Status.NOT_FOUND)
        ]
        self.assertEqual(failures, [], f"false positives on a genuine report: {failures}")

    def test_symbols_resolve_to_locations(self):
        symbols = {
            v.claim.raw: v
            for v in self.result.verdicts
            if v.claim.kind is ClaimKind.SYMBOL
        }
        self.assertIn("lib/http2.c", symbols["Curl_http2_setup"].detail)
        self.assertIn("lib/hpack.c", symbols["Curl_hpack_cleanup"].detail)


class TestRepoBehaviour(TierOneCase):
    def test_every_verdict_carries_a_reproducible_query(self):
        result = check(fixture("fabricated_hpack.md"), self.repo)
        tier1 = [v for v in result.verdicts if v.claim.tier == 1]
        self.assertTrue(tier1)
        for v in tier1:
            self.assertTrue(v.query, f"{v.claim} produced no query")

    def test_commit_sha_resolution(self):
        sha = fake_repo.head_sha(self.root)
        result = check(f"Introduced in commit {sha[:12]}.", self.repo)
        self.assertIs(result.verdicts[0].status, Status.VERIFIED)

    def test_unknown_commit_is_not_found(self):
        result = check("Introduced in commit 1234567890abcdef.", self.repo)
        self.assertIs(result.verdicts[0].status, Status.NOT_FOUND)

    def test_versions_in_code_blocks_are_skipped(self):
        # Dependency pins in a lockfile paste are not claims about our releases.
        result = check("```\nrequests==2.31.0\n```", self.repo)
        versions = [v for v in result.verdicts if v.claim.kind is ClaimKind.VERSION]
        self.assertTrue(versions)
        self.assertTrue(all(v.status is Status.SKIPPED for v in versions))


if __name__ == "__main__":
    unittest.main()
