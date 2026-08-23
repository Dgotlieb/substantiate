"""Tier 1 verification against a real git repository."""

from __future__ import annotations

import shutil
import unittest

from tests import fake_repo, fixture

from substantiate.claims import ClaimKind
from substantiate.repo import Repo
from substantiate.verdict import Status
from substantiate.verify import check


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


class TestDeclarationsOnly(TierOneCase):
    """A symbol must be substantiated by a declaration and nothing else.

    Measured on curl, the two biggest sources of false *verification* were
    comments ("* memory released by realloc() before") and call sites
    ("return realloc(ptr, size);"). Verifying a claim against a mention is
    worse than failing to verify it: it silently blesses a fabricated report.
    """

    def test_symbol_named_only_in_a_comment_is_not_declared(self):
        for name in ("Curl_ghost_alloc", "Curl_ghost_mentioned"):
            with self.subTest(name=name):
                result = check(f"The bug is in {name}().", self.repo)
                self.assertIs(result.verdicts[0].status, Status.NOT_FOUND)

    def test_symbol_only_called_is_not_declared(self):
        result = check("The bug is in Curl_called_only().", self.repo)
        self.assertIs(result.verdicts[0].status, Status.NOT_FOUND)

    def test_a_real_declaration_next_to_them_still_verifies(self):
        result = check("The bug is in Curl_http2_reset().", self.repo)
        self.assertIs(result.verdicts[0].status, Status.VERIFIED)

    def test_known_external_symbols_are_skipped_not_failed(self):
        result = check("It calls fork() and find_package() and socketpair().", self.repo)
        self.assertTrue(result.verdicts)
        for v in result.verdicts:
            with self.subTest(claim=v.claim.raw):
                self.assertIs(v.status, Status.SKIPPED)
                self.assertIn("not defined here", v.detail)


class TestForeignAttributes(TierOneCase):
    """Dotted calls on things this repository does not define.

    Python documentation is written in dotted calls, and on urllib3 this was the
    single largest class of false findings: "logging.getLogger",
    "urllib.request.getproxies", "certifi.where" and ".setLevel" were all being
    reported as undeclared. None of them is a claim that the project declares
    anything, so none of them is this tool's question to answer.
    """

    def _only(self, text):
        verdicts = check(text, self.repo).verdicts
        self.assertEqual(len(verdicts), 1, [v.claim.raw for v in verdicts])
        return verdicts[0]

    def test_python_stdlib_is_skipped(self):
        for call in ("logging.getLogger()", "urllib.request.getproxies()"):
            with self.subTest(call=call):
                v = self._only(f"It calls {call} at startup.")
                self.assertIs(v.status, Status.SKIPPED)
                self.assertIn("Python standard library", v.detail)

    def test_third_party_attribute_is_skipped(self):
        v = self._only("It calls certifi.where() to find the bundle.")
        self.assertIs(v.status, Status.SKIPPED)
        self.assertIn("certifi", v.detail)

    def test_bare_attribute_on_an_unnamed_object_is_skipped(self):
        v = self._only("The handler calls .setLevel() too early.")
        self.assertIs(v.status, Status.SKIPPED)
        self.assertIn("does not name", v.detail)

    def test_attribute_rooted_in_this_repository_is_still_checked(self):
        # Session is declared here, so Session.connect is a real claim about
        # this codebase and must not be waved through.
        v = self._only("The bug is in Session.connect().")
        self.assertIs(v.status, Status.VERIFIED)

    def test_undeclared_attribute_rooted_here_is_not_found(self):
        v = self._only("The bug is in Session.reconnect().")
        self.assertIs(v.status, Status.NOT_FOUND)

    def test_plain_python_function_verifies(self):
        v = self._only("The bug is in open_session().")
        self.assertIs(v.status, Status.VERIFIED)


class TestRefNote(TierOneCase):
    """Checking a release report against HEAD is the largest avoidable source
    of misses, so the tool says so rather than letting drift read as error."""

    def test_note_names_the_release_and_the_command(self):
        result = check("Reproduced against 8.12.1 on Linux.", self.repo)
        self.assertEqual(len(result.notes), 1)
        note = result.notes[0]
        self.assertIn("v8.12.1", note)
        self.assertIn("--ref v8.12.1", note)

    def test_no_note_when_already_pinned_to_a_release(self):
        pinned = Repo(self.root, "v8.12.1")
        self.assertEqual(check("Reproduced against 8.12.1.", pinned).notes, [])

    def test_no_note_when_the_report_names_no_release(self):
        self.assertEqual(check("The bug is in lib/http2.c today.", self.repo).notes, [])

    def test_no_note_for_a_version_that_is_not_a_tag(self):
        self.assertEqual(check("Reproduced against 8.9.0.", self.repo).notes, [])


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


class TestBackendLimits(TierOneCase):
    """A backend that cannot decide a claim must say so, not report a miss.

    The regex resolver knows two shapes of C declaration: a function definition
    at column zero, and a #define. An enum constant is neither, and the macro
    form is indistinguishable by pattern from a call site passing the same name
    as an argument -- matching it would substantiate fabricated claims, which is
    the worse failure. So the honest answer is that this backend cannot say.
    """

    def verdict_for(self, text, name, resolver):
        from substantiate.verify import check
        for v in check(text, self.repo, resolver=resolver).verdicts:
            if v.claim.data.get("name") == name:
                return v
        raise AssertionError(f"no verdict for {name}")

    def test_regex_backend_skips_constants_rather_than_reporting_a_miss(self):
        from substantiate.symbols import DEFAULT_RESOLVER
        v = self.verdict_for(
            "The flaw affects FIXTURE_OPT_VERIFYPEER handling.",
            "FIXTURE_OPT_VERIFYPEER",
            DEFAULT_RESOLVER,
        )
        self.assertIs(v.status, Status.SKIPPED)

    def test_the_skip_names_what_would_answer_the_question(self):
        from substantiate.symbols import DEFAULT_RESOLVER
        v = self.verdict_for(
            "The flaw affects FIXTURE_OPT_VERIFYPEER handling.",
            "FIXTURE_OPT_VERIFYPEER",
            DEFAULT_RESOLVER,
        )
        self.assertIsNotNone(v.hint)
        self.assertIn("treesitter", v.hint)

    def test_a_define_still_verifies_under_the_regex_backend(self):
        # The skip must not swallow constants this backend genuinely can resolve.
        from substantiate.symbols import DEFAULT_RESOLVER
        v = self.verdict_for(
            "Guarded by FIXTURE_OPT which expands the option.",
            "FIXTURE_OPT",
            DEFAULT_RESOLVER,
        )
        self.assertIs(v.status, Status.VERIFIED)


class TestTreeSitterConstants(TierOneCase):
    """Tree-sitter parses, so it owns constants -- including the macro form."""

    def setUp(self):
        from substantiate import treesitter
        if not treesitter.available():
            self.skipTest("tree-sitter not installed")
        self.resolver = treesitter.TreeSitterSymbolResolver()

    def verdict_for(self, text, name):
        from substantiate.verify import check
        for v in check(text, self.repo, resolver=self.resolver).verdicts:
            if v.claim.data.get("name") == name:
                return v
        raise AssertionError(f"no verdict for {name}")

    def test_plain_enumerator_verifies(self):
        v = self.verdict_for("Affects FIXTURE_OPT_TIMEOUT.", "FIXTURE_OPT_TIMEOUT")
        self.assertIs(v.status, Status.VERIFIED)

    def test_macro_wrapped_enumerator_verifies(self):
        v = self.verdict_for("Affects FIXTURE_OPT_MAXCONNECTS.", "FIXTURE_OPT_MAXCONNECTS")
        self.assertIs(v.status, Status.VERIFIED)

    def test_a_fabricated_constant_is_still_not_found(self):
        # The whole point: skipping must not become blanket amnesty.
        v = self.verdict_for("Affects FIXTURE_OPT_INVENTED.", "FIXTURE_OPT_INVENTED")
        self.assertIs(v.status, Status.NOT_FOUND)


class TestForeignLibraries(TierOneCase):
    """Symbols owned by platform and third-party libraries.

    Every name here was an unexplained miss on curl's published advisories.
    A report saying a bug is reached through LoadLibrary or SSL_OP_ALL is not
    claiming curl declares them, so a miss is a false finding -- and unlike a
    renamed internal, no near-miss hint can soften it, because the declaration
    is in somebody else's tree.
    """

    def _only(self, text):
        verdicts = check(text, self.repo).verdicts
        self.assertEqual(len(verdicts), 1, [v.claim.raw for v in verdicts])
        return verdicts[0]

    def test_win32_api_is_skipped(self):
        for call in ("LoadLibrary()", "CertGetNameString()"):
            with self.subTest(call=call):
                v = self._only(f"It reaches the flaw through {call}.")
                self.assertIs(v.status, Status.SKIPPED)
                self.assertIn("Windows API", v.detail)

    def test_openssl_constant_is_skipped(self):
        v = self._only("The build sets SSL_OP_ALL unconditionally.")
        self.assertIs(v.status, Status.SKIPPED)
        self.assertIn("OpenSSL", v.detail)

    def test_ldap_symbols_are_skipped(self):
        for name in ("ldap_get_attribute_ber()", "LDAP_SUCCESS"):
            with self.subTest(name=name):
                v = self._only(f"The handler checks {name} before continuing.")
                self.assertIs(v.status, Status.SKIPPED)
                self.assertIn("LDAP", v.detail)

    def test_limits_macro_is_skipped(self):
        v = self._only("The length is compared against UINT_MAX.")
        self.assertIs(v.status, Status.SKIPPED)
        self.assertIn("C standard library", v.detail)

    def test_posix_signal_call_is_skipped(self):
        v = self._only("The handler calls siglongjmp() from the alarm.")
        self.assertIs(v.status, Status.SKIPPED)
        self.assertIn("C standard library", v.detail)


class TestBuildSystemDeclarations(TierOneCase):
    """Build variables are declared in the build system, not in any source file.

    Documentation for a C project is largely build instructions. Measured on
    curl's docs/, every documented CMake option -- BUILD_SHARED_LIBS,
    BROTLI_INCLUDE_DIR, CARES_LIBRARY and hundreds more -- was reported as an
    undeclared symbol, because the resolver read C and nothing else. They are
    real declarations in CMakeLists.txt and the project's find modules.
    """

    def _only(self, text):
        verdicts = check(text, self.repo).verdicts
        self.assertEqual(len(verdicts), 1, [v.claim.raw for v in verdicts])
        return verdicts[0]

    def test_option_is_a_declaration(self):
        v = self._only("Set FIXTURE_BUILD_TESTS to OFF to skip them.")
        self.assertIs(v.status, Status.VERIFIED)
        self.assertIn("CMakeLists.txt", v.detail)

    def test_set_is_a_declaration(self):
        v = self._only("The default is FIXTURE_DEFAULT_TIMEOUT seconds.")
        self.assertIs(v.status, Status.VERIFIED)

    def test_cmake_commands_are_case_insensitive(self):
        v = self._only("Pass FIXTURE_LEGACY_UPPERCASE to opt in.")
        self.assertIs(v.status, Status.VERIFIED)

    def test_find_library_and_find_path_declare_their_result(self):
        for name in ("FIXTURE_SSL_LIBRARY", "FIXTURE_SSL_INCLUDE_DIR"):
            with self.subTest(name=name):
                v = self._only(f"Point {name} at your build.")
                self.assertIs(v.status, Status.VERIFIED)
                self.assertIn(".cmake", v.detail)

    def test_a_comment_still_does_not_declare_anything(self):
        # The rule that held for C holds here: prose mentioning a name, even
        # inside the build file, must not substantiate a claim about it.
        v = self._only("Configure FIXTURE_ONLY_IN_A_COMMENT before building.")
        self.assertIsNot(v.status, Status.VERIFIED)


class TestReservedNamespaces(TierOneCase):
    """Names a tool reserves for itself are that tool's, not the project's.

    CMake reserves the CMAKE_ prefix for its own variables. curl's build
    documentation is full of them -- CMAKE_INSTALL_PREFIX, CMAKE_BUILD_TYPE,
    CMAKE_C_FLAGS -- and none is a claim that curl declares anything.
    """

    def _only(self, text):
        verdicts = check(text, self.repo).verdicts
        self.assertEqual(len(verdicts), 1, [v.claim.raw for v in verdicts])
        return verdicts[0]

    def test_reserved_cmake_variables_are_skipped(self):
        for name in ("CMAKE_INSTALL_PREFIX", "CMAKE_BUILD_TYPE", "CMAKE_C_FLAGS"):
            with self.subTest(name=name):
                v = self._only(f"Pass {name} when configuring.")
                self.assertIs(v.status, Status.SKIPPED)
                self.assertIn("CMake", v.detail)

    def test_a_project_variable_that_merely_starts_similarly_is_still_checked(self):
        # The prefix must be the reserved one, not any name beginning with it.
        v = self._only("Set FIXTURE_BUILD_TESTS to OFF.")
        self.assertIs(v.status, Status.VERIFIED)
