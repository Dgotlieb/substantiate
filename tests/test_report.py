"""Copy discipline, enforced.

The project's central promise is that it reports findings and never renders a
judgement about a report or its author. That promise lives in strings, so it is
tested like any other behaviour -- and the tests iterate over every registered
format, so a reporter added later cannot quietly opt out.
"""

from __future__ import annotations

import json
import shutil
import unittest

from tests import fake_repo, fixture

from corroborate.repo import Repo
from corroborate.report import BANNED_WORDS, DISCLAIMER, render
from corroborate.verify import check

FORMATS = ("terminal", "markdown", "json")


class ReportCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = fake_repo.build()
        cls.repo = Repo(cls.root, "HEAD")
        cls.result = check(fixture("fabricated_hpack.md"), cls.repo)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)


class TestCopyDiscipline(ReportCase):
    def test_every_format_carries_the_disclaimer(self):
        for fmt in FORMATS:
            with self.subTest(fmt=fmt):
                out = render(self.result, fmt, color=False)
                needle = DISCLAIMER if fmt != "terminal" else DISCLAIMER.split(".")[0]
                self.assertIn(needle.split(",")[0], out)

    def test_tool_authored_copy_avoids_accusatory_vocabulary(self):
        # Scoped to strings the tool writes. Text quoted from the report itself
        # is the contributor's, and is reproduced verbatim on purpose.
        authored = [DISCLAIMER]
        for v in self.result.verdicts:
            authored.append(v.detail)
            if v.hint:
                authored.append(v.hint)
        blob = " ".join(authored).lower()
        for word in BANNED_WORDS:
            with self.subTest(word=word):
                self.assertNotIn(word, blob)

    def test_no_format_claims_the_report_is_wrong(self):
        for fmt in FORMATS:
            with self.subTest(fmt=fmt):
                out = render(self.result, fmt, color=False).lower()
                for phrase in ("this report is", "the reporter", "likely fake", "reject"):
                    self.assertNotIn(phrase, out)


class TestRendering(ReportCase):
    def test_json_is_parseable_and_stable(self):
        data = json.loads(render(self.result, "json"))
        self.assertEqual(data["tool"], "corroborate")
        self.assertEqual(data["version"], 1)
        self.assertEqual(len(data["claims"]), len(self.result.verdicts))
        for claim in data["claims"]:
            self.assertIn("status", claim)
            self.assertIn("query", claim)

    def test_markdown_surfaces_unresolved_claims_without_a_click(self):
        out = render(self.result, "markdown")
        head = out.split("<details>")[0]
        self.assertIn("src/http2/hpack.c", head)

    def test_markdown_folds_away_the_full_list(self):
        out = render(self.result, "markdown")
        self.assertIn("<details>", out)
        self.assertIn("</details>", out)

    def test_terminal_output_is_plain_without_color(self):
        out = render(self.result, "terminal", color=False)
        self.assertNotIn("\033[", out)

    def test_terminal_output_colors_when_asked(self):
        self.assertIn("\033[", render(self.result, "terminal", color=True))

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            render(self.result, "yaml")


if __name__ == "__main__":
    unittest.main()
