"""Tier 2 verifiers.

No test here touches the network. Every one feeds a recorded OSV payload to the
parsing, which is where the judgement lives -- a timeout is not evidence, and a
test that needs the internet to pass is not evidence either.
"""

from __future__ import annotations

import shutil
import unittest

from tests import fake_repo

from substantiate.repo import Repo
from substantiate.verify.external import _osv_relevance, _project_names


class RelevanceCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = fake_repo.build()
        cls.repo = Repo(cls.root, "HEAD")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)


class TestProjectNames(RelevanceCase):
    def test_the_directory_name_is_one_of_them(self):
        self.assertIn(self.repo.path.name.lower(), _project_names(self.repo))

    def test_underscores_and_dots_normalise_to_hyphens(self):
        # PyPI treats them as equivalent, so "verdict_mcp" must match a CVE
        # that names "verdict-mcp" or the hint fires on an honest report.
        from substantiate.verify.external import _normalise

        self.assertEqual(_normalise("verdict_mcp"), "verdict-mcp")
        self.assertEqual(_normalise("Verdict.MCP"), "verdict-mcp")


class TestOsvRelevance(RelevanceCase):
    def hint(self, payload):
        return _osv_relevance(payload, self.repo)

    def test_an_unrelated_advisory_is_named(self):
        # The one that started this: a real Linux kernel CVE cited in a report
        # about a Python project resolved and read as corroboration.
        hint = self.hint({
            "id": "CVE-2026-45871",
            "affected": [{"package": {"name": "linux", "ecosystem": "Linux"}}],
        })
        self.assertIsNotNone(hint)
        self.assertIn("linux", hint)

    def test_a_matching_advisory_says_nothing(self):
        name = self.repo.path.name
        self.assertIsNone(self.hint({
            "affected": [{"package": {"name": name, "ecosystem": "PyPI"}}],
        }))

    def test_a_matching_advisory_says_nothing_across_separators(self):
        name = self.repo.path.name.replace("-", "_")
        self.assertIsNone(self.hint({
            "affected": [{"package": {"name": name, "ecosystem": "PyPI"}}],
        }))

    def test_a_git_range_naming_this_repository_counts_as_a_match(self):
        # Kernel and C advisories often carry no package name at all, only the
        # repository the fix landed in.
        self.assertIsNone(self.hint({
            "affected": [{
                "ranges": [{
                    "type": "GIT",
                    "repo": f"https://github.com/example/{self.repo.path.name}",
                }],
            }],
        }))

    def test_silence_when_osv_says_nothing_about_packages(self):
        # No affected list is not evidence of irrelevance. Erring toward
        # silence is the rule: an unhinted verdict beats a wrong hint.
        self.assertIsNone(self.hint({"id": "CVE-2020-0001"}))
        self.assertIsNone(self.hint({"id": "CVE-2020-0001", "affected": []}))
        self.assertIsNone(self.hint({"affected": [{"package": {}}]}))

    def test_one_matching_entry_among_many_is_enough(self):
        name = self.repo.path.name
        self.assertIsNone(self.hint({
            "affected": [
                {"package": {"name": "linux", "ecosystem": "Linux"}},
                {"package": {"name": name, "ecosystem": "PyPI"}},
            ],
        }))

    def test_the_hint_lists_a_bounded_number_of_packages(self):
        hint = self.hint({
            "affected": [
                {"package": {"name": f"pkg{i}", "ecosystem": "PyPI"}} for i in range(20)
            ],
        })
        self.assertIsNotNone(hint)
        self.assertLessEqual(len(hint), 200)


if __name__ == "__main__":
    unittest.main()
