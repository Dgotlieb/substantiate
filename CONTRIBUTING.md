# Contributing

Run the suite first. There is no install step and there are no dependencies:

```sh
python3 -m unittest discover -s tests -t .
```

## The rule that overrides everything else

Substantiate verifies claims, never authorship. A change that infers whether text was
AI-generated, scores contributors, enables auto-closing by default, or phrases output as
an accusation will be declined regardless of how well it works. This is not a style
preference — it is the reason maintainers can run this without poisoning their own
contributor relationships.

`tests/test_report.py` enforces the vocabulary rule mechanically across every output
format, including ones added after this was written.

## Precision beats recall, everywhere

A claim we fail to extract is a check that does not run. A claim we invent is a finding
against a contributor who never made it. When a heuristic is uncertain, it should stay
quiet.

The same applies to verdicts. Whenever a `not_found` has a plausible innocent explanation
— the file moved, the symbol was renamed, the version is on an unreleased branch — the
verdict must carry a `hint` saying so. A `not_found` with no hint on a genuine report is a
bug, not a tuning issue.

## Good first contributions

Each of these is self-contained, has an obvious test shape, and needs no understanding of
the rest of the system.

### A language pack

`src/substantiate/symbols.py` resolves symbols with declaration patterns per language.
Adding one means adding an entry to `_DECLARATIONS` (and `_ALIASES` for dialects that
share it) plus tests. Currently covered: C/C++, Python, JavaScript/TypeScript, Go, Rust,
Java, Ruby, PHP.

Wanted: Swift, Elixir, Haskell, Zig, Perl, Lua, shell.

A pattern must match a *declaration*, never a call site or a mention in a comment. If you
cannot express that as a regex for your language, that is the signal to write a
tree-sitter backend instead — see below.

### A tree-sitter backend

The regex resolver is the zero-dependency default, not the ceiling. `SymbolResolver` in
`symbols.py` is the seam: implement `find(repo, name) -> list[Location]` and
`languages() -> set[str]`, register it, and extraction, verdicts and reporting are all
unchanged. The optional dependency group `substantiate[treesitter]` is reserved for this.

This is the single highest-value open piece of work in the project.

### A registry resolver

`src/substantiate/verify/external.py` holds Tier 2. Each resolver is one function taking a
`Claim` and returning a `Verdict`. Wanted:

- package registries (PyPI, npm, crates.io, Go modules, Maven, RubyGems) — a report citing
  a package that does not exist is a strong signal, and this is the same check that
  catches slopsquatted dependencies
- GHSA identifiers alongside CVE
- a response cache, so the same fabricated identifier is not looked up repeatedly

Every Tier 2 resolver must degrade to `Status.ERROR`, never `NOT_FOUND`, when the network
fails. A timeout is not evidence.

### A report adapter

Every disclosure platform exports a different shape, and the private ones matter most.
Wanted: HackerOne export, GitHub draft security advisories, Bugzilla, plain email with
attachments. An adapter is a pure function to `(text, attachments)` with fixture tests.

### A reproduction recipe

Tier 3 will run a project's own build and proof-of-concept steps in a sandbox, driven by a
`.substantiate.yml` committed to that project's repository. The schema is not settled; if
you maintain a project that would use this, opening an issue describing your build
invocation is more useful right now than code.

## Testing conventions

- Standard library `unittest`. No test dependencies.
- Anything touching a repository builds one with `tests/fake_repo.py`. Never reach for a
  fixture checked in as a real project.
- Every extraction change needs a precision test (something that must *not* be extracted),
  not only a recall test.
- Tier 2 tests must not require the network. Test the parsing, stub the fetch.

## Cutting a release

The version lives in exactly one place, `src/substantiate/__init__.py`. `pyproject.toml`
reads it from there and the suite fails if the two ever disagree, so there is no second
file to remember.

1. Bump `__version__`, commit, and let CI go green.
2. Tag it and push the tag:
   ```sh
   git tag -a v0.1.2 -m "Release 0.1.2" && git push origin v0.1.2
   ```
3. Publish a GitHub release for that tag. *Publishing* is the trigger — a draft does
   nothing. `release.yml` then builds, reinstalls from its own wheel, smoke tests it, and
   uploads to PyPI over Trusted Publishing, with no token stored anywhere.
4. Nothing. The `v1` tag moves itself.

Step 4 used to be a manual `git tag -f`, and it is worth knowing why it is not any more.
The README tells adopters to pin the Action at `@v1`, following the convention every
published Action uses. A floating tag only floats if something moves it, and forgetting to
move it fails in the worst possible way: every adopter stays on the previous release,
their workflow still green, still silent, never receiving the fix. There is nothing to
notice and no error to read. So the `major-tag` job in `release.yml` does it, and
`ACTION_MAJOR` there is the one line to change if the Action's inputs ever break
compatibility.

## Scope

Claims are checkable, falsifiable statements about the world. If a proposal cannot be
phrased as "X exists / X does not exist, and here is the query that shows it", it is
probably out of scope — file an issue and let's talk before writing it.
