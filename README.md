# Corroborate

**An evidence gate for open-source contributions.** It checks whether the claims in an
issue, pull request, or security report correspond to anything real — before a maintainer
spends an hour proving they don't.

```
CORROBORATE  11 claims checked · 2 verified · 5 not found · 4 skipped

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

**Corroborate verifies claims, never authorship.**

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
pipx install corroborate     # or: pip install corroborate
```

Runs on Python 3.10+.

## Use

```sh
# A report saved to a file, checked against a released tag
corroborate check report.md --repo ~/src/curl --ref v8.12.1

# A GitHub issue, piped in
gh issue view 4471 --json body -q .body | corroborate check - --repo .

# Also check CVEs, CWEs, RFCs and links against public registries
corroborate check report.md --online

# For your own automation
corroborate check report.md --format json
```

Because most reports that hurt most arrive privately — through HackerOne, a security list,
or a draft advisory — the core takes *text plus a repository path*, not a webhook. The CLI
works on anything you can paste into a file, and nothing leaves your machine unless you
pass `--online`.

Exit status is 0 even when claims do not resolve. That is deliberate: a non-zero exit
invites people to wire this up as an auto-close gate, which is the one use it must not
have. Automation that genuinely needs to branch on the outcome can opt into `--exit-code`,
and should read the JSON.

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
report's own quoted diff, must not corroborate itself.

## Being fair to genuine reports

Real reports fail checks too: code gets renamed, files move, reports target unreleased
branches, path roots get omitted. Every such case is a false positive that costs a
contributor credibility they earned.

So `not found` never stands alone when the tool can explain it. A path that fails because
the file moved says where it is now. A symbol that fails gets its closest declared
neighbours. A line reference past the end of a real file says so explicitly.

If you find a genuine report that Corroborate marks down without a hint, that is a bug —
please [open an issue](../../issues) with the report and the repo.

## Contributing

The people who need this are the people who write open source, which makes adoption and
contribution the same flywheel. Most useful work is small, independent, and testable
without understanding the core: language packs, registry resolvers, report adapters,
reproduction recipes. See [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
git clone https://github.com/USER/corroborate && cd corroborate
python3 -m unittest discover -s tests -t .   # no install, no dependencies
```

## Measured, not assumed

The project's central risk is not missing fabricated reports. It is marking down honest
ones. So the false-positive rate is measured against corpora known to be accurate — a
project's own in-tree documentation is maintainer-written and references real code, so
anything flagged there is either genuine drift or a bug in this tool.

```sh
python3 benchmarks/false_positives.py ~/src/curl docs --limit 150
```

Against curl (4,449 files), the first run marked **54.9%** of Tier 1 claims as not found.
Four causes, each now fixed and pinned by a regression test built from the actual miss:

- capitalised words before a parenthesis read as calls — `OpenSSL (or LibreSSL)`,
  `Schannel`, `NTLM`, `Boolean`
- illustrative bare filenames read as paths — `cookies.txt`, `node.js`
- schemeless URLs read as paths — `example.com/moo2.txt`
- the date `20190808` parsed as a commit SHA

Current rate on that corpus: **30.3% not found, of which 19.7% is unexplained.** That
second number is the one that matters. A miss carrying a hint — "a file of that name
exists at `lib/hpack.c`" — is useful to everyone. A bare miss on an honest report is what
gets the tool uninstalled.

Some of the remainder is the tool being right: `lib/doh.c`, `curl_formparse` and
`curl_easy_options` genuinely are absent from curl at HEAD, so those are real
documentation drift. The rest is known and tractable — build-system identifiers
(`find_package`), system calls (`fork`), and constants defined through macro indirection
(`CURLOPT_SSLVERSION`), which is the case a tree-sitter backend fixes.

## Status

Early. The v0.1 surface is Tier 1 and Tier 2 with deterministic extraction. It is a
filter, not an oracle: a fabricated report that cites only real files, real symbols and a
real CVE will pass every check. Corroborate removes the cheapest fiction, which is most of
it today, and will be adapted to.

## License

Apache-2.0.
