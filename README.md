# Substantiate

**An evidence gate for open-source contributions.** It checks whether the claims in an
issue, pull request, or security report correspond to anything real — before a maintainer
spends an hour proving they don't.

```
SUBSTANTIATE  11 claims checked · 2 verified · 5 not found · 4 skipped

CODE REFERENCES                                       ref: v8.12.1
  not found  8.9.0                                  no matching release tag
                                                    ↳ 3 tags exist; this version is not among them
  not found  src/http2/hpack.c                      no such path at v8.12.1
                                                    ↳ a file of that name exists at lib/hpack.c
  not found  Curl_hpack_decode                      no matching declaration in tree
                                                    ↳ closest declared symbols: Curl_hpack_decode_header
  not found  lib/http2.c:1102                       file has 78 lines
                                                    ↳ the file exists but is shorter than the cited line
  verified   lib/http2.c:42                         line exists (78 total)

This is a triage signal, not a verdict. Claims can fail because code was
renamed, the report targets an unlisted branch, or a path root was omitted.
Every check above is reproducible.
```

A maintainer reading that knows in seconds that the report describes a file, a function,
and a released version that have never coexisted. They have not been told what to
conclude. They have been handed the thirty minutes back.

## Why

In January 2026 curl [ended its bug bounty program](https://www.bleepingcomputer.com/news/security/curl-ending-bug-bounty-program-after-flood-of-ai-slop-reports/);
its valid-report rate had collapsed from roughly one in six to one in thirty. Node.js
received a 19,000-line generated pull request that consumed days of review. Jazzband, the
collective maintaining 84 Python packages, shut down entirely.

The cost is asymmetric, and that is the whole problem. Producing a confident, well-formatted,
entirely fictional vulnerability report takes seconds. Refuting one takes a domain expert
half an hour of reading code the report describes but does not match.

## The one design rule

**Substantiate verifies claims, never authorship.**

It is not a detector, and that is a deliberate constraint rather than a missing feature.
Detectors of generated text do not work reliably, and a tool that accuses contributors of
using AI would be both frequently wrong and socially corrosive.

So it never reasons about who or what wrote a report. It takes the falsifiable claims the
report makes about the world — this file, this function, this line, this CVE, this version —
and checks each against the repository and the public record. A human who writes a careful
report with AI assistance passes cleanly. A fabricated report fails on its citations,
because fabricated citations are what fabrication produces.

Concretely, the project will never:

- infer whether text was AI-generated,
- score or rank contributors,
- auto-close anything by default, at any confidence,
- phrase output as an accusation.

Every verdict carries the exact query that produced it, so a maintainer can re-run any
check by hand and disagree with it.

## Install

Tier 1 has no dependencies and never will — maintainers running this on untrusted reports
should not have to audit a dependency tree to do it.

```sh
pipx install substantiate               # zero dependencies
pipx install "substantiate[treesitter]" # optional: parse instead of pattern-match
```

Runs on Python 3.10+. The optional extra swaps regex symbol matching for a real parser,
which resolves declaration forms patterns cannot reach — enum constants defined through
macro indirection, for one. It is selected automatically when importable, and measurably
more accurate, but the default stays dependency-free on purpose: a maintainer running this
on untrusted reports should not have to audit a dependency tree first.

## Use

```sh
# A report saved to a file, checked against a released tag
substantiate check report.md --repo ~/src/curl --ref v8.12.1

# A GitHub issue, piped in
gh issue view 4471 --json body -q .body | substantiate check - --repo .

# Also check CVEs, CWEs, RFCs and links against public registries
substantiate check report.md --online

# For your own automation
substantiate check report.md --format json
```

### Check against the release, not `HEAD`

This is the single highest-leverage flag, and the most common way to get misleading
output. A vulnerability report describes the code **as it was released**. Between that
release and your `HEAD`, files get renamed, functions get refactored, whole modules move.
Check the report against `HEAD` and that ordinary drift comes back looking like fabrication.

```sh
# Wrong: the report is about 8.9.0, but this checks today's code
substantiate check report.md --repo ~/src/curl

# Right: check the release the report actually names
substantiate check report.md --repo ~/src/curl --ref v8.9.0
```

When a report names a release that exists as a tag and you checked something else,
Substantiate says so and gives you the command:

```
note: This report names a release (v8.12.1) but was checked against HEAD. Code
moves between releases, so some misses above may be drift rather than error. To
check the release itself: --ref v8.12.1
```

Two practical notes. Version claims only resolve if the tags are present, so clone with
full history — a `--depth 1` checkout has no tags and every version claim is skipped. And
if the report names no version at all, that is worth asking about before triaging it: a
report that cannot say which release it affects usually cannot be reproduced either.

Because most reports that hurt most arrive privately — through HackerOne, a security list,
or a draft advisory — the core takes *text plus a repository path*, not a webhook. The CLI
works on anything you can paste into a file, and nothing leaves your machine unless you
pass `--online`.

Exit status is 0 even when claims do not resolve. That is deliberate: a non-zero exit
invites people to wire this up as an auto-close gate, which is the one use it must not
have. Automation that genuinely needs to branch on the outcome can opt into `--exit-code`,
and should read the JSON.

## Run it on every issue

Copy this into your repository as `.github/workflows/substantiate.yml`. It posts one
comment when an issue or pull request is opened, and only when something failed to
resolve — a wall of green on a good report is noise.

```yaml
name: Substantiate

on:
  issues:
    types: [opened]
  pull_request_target:
    types: [opened]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha || github.sha }}
          fetch-depth: 0   # tags and history, so version and commit claims resolve

      - id: substantiate
        uses: Dgotlieb/substantiate@c6ae746b882a2454bcb8f2fa5d8587278299f8c3  # v0.1.3
        with:
          report: ${{ github.event.issue.body || github.event.pull_request.body }}
          online: "true"

      - name: Comment when claims did not resolve
        if: steps.substantiate.outputs.unresolved != '0'
        env:
          GH_TOKEN: ${{ github.token }}
          BODY: ${{ steps.substantiate.outputs.markdown }}
          NUMBER: ${{ github.event.issue.number || github.event.pull_request.number }}
        run: gh issue comment "$NUMBER" --repo "$GITHUB_REPOSITORY" --body "$BODY"
```

That pin is a commit SHA on purpose, and it is the one line above worth arguing about.

`pull_request_target` runs with a token that can comment. This workflow is careful about
the part most people get wrong — it checks out the *base* repository, never the pull
request head, so nothing a contributor wrote is executed. Resolving the action itself
through a tag would undo that care: a tag is mutable, and whoever can move it changes what
runs inside your workflow, with your writable token, without you touching a line. That is
not hypothetical — `tj-actions/changed-files` was compromised in 2025 by exactly that
route. A SHA is the only reference GitHub will not let anyone repoint.

This project publishes a moving `v1` tag and moves it automatically on every release,
which is convenient and is precisely why it is the wrong trust anchor here. Use `@v1` only
in an `issues:`-only workflow, where no writable token is exposed to untrusted input:

```yaml
on:
  issues:
    types: [opened]
```

If you run Dependabot, add `github-actions` to its ecosystems and it will bump the SHA and
tell you which version it moved to, which costs you nothing and keeps the guarantee.

Two things worth understanding before you enable it. `fetch-depth: 0` is not optional:
without tags, every version and commit claim is skipped, which is most of what a report
about a release asserts. And `pull_request_target` runs with a token that can comment, so
the workflow checks out the **base** repository and never the pull request's head —
nothing from the contributor is executed, and their description is read as data.

The action exposes `markdown`, `json` and `unresolved`, so a project that wants to label
rather than comment, or route to a triage channel, can branch on the count without
parsing text.

## What gets checked

Ordered by cost per unit of signal. Tier 1 needs no network and no model, runs in under a
second, and catches most fabricated reports outright — so it is the default and everything
else is opt-in.

| | Checks | Resolved against | Status |
|---|---|---|---|
| **Tier 1** | file paths, symbols, line numbers, version ranges, commit SHAs | the repository at `--ref` | shipping |
| **Tier 2** | CVE, CWE, RFC sections, link liveness | OSV, MITRE, RFC Editor | shipping, `--online` |
| **Tier 3** | proof-of-concept execution, patch apply and build | a sandbox, per-project recipe | planned |
| **Tier 4** | does the diff match its own description | the diff alone | planned |

Symbols resolve as *declarations*, not as strings — a mention in a comment, or in the
report's own quoted diff, must not substantiate itself.

## Being fair to genuine reports

Real reports fail checks too: code gets renamed, files move, reports target unreleased
branches, path roots get omitted. Every such case is a false positive that costs a
contributor credibility they earned.

So `not found` never stands alone when the tool can explain it. A path that fails because
the file moved says where it is now. A symbol that fails gets its closest declared
neighbours. A line reference past the end of a real file says so explicitly.

If you find a genuine report that Substantiate marks down without a hint, that is a bug —
please [open an issue](../../issues) with the report and the repo.

## Contributing

The people who need this are the people who write open source, which makes adoption and
contribution the same flywheel. Most useful work is small, independent, and testable
without understanding the core: language packs, registry resolvers, report adapters,
reproduction recipes. See [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
git clone https://github.com/Dgotlieb/substantiate && cd substantiate
python3 -m unittest discover -s tests -t .   # no install, no dependencies
```

## Measured, not assumed

The project's central risk is not missing fabricated reports. It is marking down honest
ones. So the false-positive rate is measured against corpora known to be accurate — a
project's own in-tree documentation is maintainer-written and references real code, so
anything flagged there is either genuine drift or a bug in this tool.

```sh
python3 benchmarks/false_positives.py ~/src/curl docs --limit 150
python3 benchmarks/real_advisories.py ~/src/curl
```

Against curl (4,449 files), the first run marked **54.9%** of Tier 1 claims as not found.
Four causes, each now fixed and pinned by a regression test built from the actual miss:

- capitalised words before a parenthesis read as calls — `OpenSSL (or LibreSSL)`,
  `Schannel`, `NTLM`, `Boolean`
- illustrative bare filenames read as paths — `cookies.txt`, `node.js`
- schemeless URLs read as paths — `example.com/moo2.txt`
- the date `20190808` parsed as a commit SHA

Current rates, with the tree-sitter backend:

| Corpus | Claims | Not found | Unexplained |
|---|---|---|---|
| curl advisories, at the affected release | 129 | 9.3% | **3.1%** |
| curl advisories, at HEAD | 124 | 12.1% | **5.6%** |
| curl `docs/` (C, 4,449 files) | 1,165 | 40.7% | **32.0%** |
| urllib3 markdown (Python) † | 14 | 7.1% | **0.0%** |

† urllib3 documents itself in reStructuredText and this harness reads only Markdown, so
the Python row covers the nine `.md` files in the repository rather than `docs/`. It is a
thin corpus and the zero should be read as "nothing left to find here", not as a general
rate. Extending the harness to `.rst` would say more about Python projects than any
further tuning against curl.

The pinned advisory row was 29.5% and 24.0% until the backend learned to read enum
constants the C grammar cannot parse. curl declares every option through a macro, and
through 7.62 it pasted the name together — `CINIT(SSL_VERIFYPEER, LONG, 64)`, so
`CURLOPT_SSL_VERIFYPEER` appears zero times in the header that declares it. Since
advisories name the API constant almost every time, and the pinned row checks each one
against the old release it actually describes, that single class of miss was most of the
column. All four survivors are internal functions curl has since renamed or removed.

The documentation row did not move, which is the honest result rather than a
disappointing one: it is measured at HEAD, where the constants resolved already, and what
remains is dominated by build variables (`CURL_ZLIB`, `ANDROID_NDK_HOME`) and by names
curl's own prose gets wrong — `CURLOPT_CONNECTIMEOUT` is a typo for
`CURLOPT_CONNECTTIMEOUT` and this tool is right to say it resolves to nothing.

The unexplained column is the one that matters. A miss carrying a hint — "a file of that
name exists at `lib/hpack.c`" — is useful to everyone. A bare miss on an honest report is
what gets the tool uninstalled.

Read that column with one caveat: it counts misses that carry no hint, so a backend that
resolves the same claims but explains fewer of them scores worse. Measured on the
advisories at HEAD, the regex resolver reported fewer unexplained misses than tree-sitter
while resolving strictly less, purely because it offers near-miss hints where tree-sitter
offers none. The column tracks the experience of the person reading the report, which is
what it is for, but it is not a measure of resolution on its own.

The two advisory rows are the workload the tool actually exists for, and were added after
the documentation corpora had already been tuned against. They immediately showed what
documentation could not: real security reports are prose about behaviour, naming the API
constant almost every time and a file path or an internal function name almost never.
Extraction found three checkable claims across twenty-five advisories until named
constants were extracted at all.

That change is also why the curl `docs/` row moved from 67 claims to 1,165. Documentation
for a C project is largely build instructions, and once constants were claimed, every
documented build variable became a claim. Most now resolve — the resolver reads
CMakeLists.txt and the project's find modules, where those options are genuinely declared
— and constants in namespaces the repository never declares into are skipped rather than
reported, since `BROTLI_USE_STATIC_LIBS` belongs to brotli. The rate is still well above
where it sat before constants existed, and driving it down is the open work.

Adding the second corpus was worth more than any amount of tuning against the first.
Python documentation is written in dotted calls, and `logging.getLogger`,
`urllib.request.getproxies`, `certifi.where` and `.setLevel` were all being reported as
undeclared — 6 of 8 misses on urllib3, a class that a C-only corpus could never surface.
None of them is a claim that the project declares anything. Attributes rooted outside the
repository now resolve as skipped, and the fixture repository is no longer C-only.

Most of the remainder is the tool being right. `curl_easy_options`, `curl_formparse`,
`dohprobe` and `readwrite_data` genuinely are absent from curl at HEAD, and
`CURLOPT_CONNECTIMEOUT` is documentation drift — the option is spelled `CONNECTTIMEOUT`.
Symbols owned by libc, Win32, OpenSSL and OpenLDAP, `ldap_bind_s` among them, are skipped
rather than reported: a report naming one is not claiming this project declares it.

### False verification is the worse failure

The benchmark counts unresolved claims, so it barely registers the opposite error:
substantiating a claim against something that is not a declaration. Measured on curl, two
patterns were silently blessing fabricated claims —

```c
 * memory released by realloc() before otherwise would log it.   /* a comment */
   return realloc(ptr, size);                                    /* a call site */
```

— both of which the regex resolver was reporting as declarations of `realloc`. Comments
are now stripped before matching, call sites are rejected, and C declarations must begin
at column zero with their return type. A claim is never substantiated by prose that merely
mentions it, including prose inside the code.

## Status

Early. The v0.1 surface is Tier 1 and Tier 2 with deterministic extraction. It is a
filter, not an oracle: a fabricated report that cites only real files, real symbols and a
real CVE will pass every check. Substantiate removes the cheapest fiction, which is most of
it today, and will be adapted to.

## License

Apache-2.0.
