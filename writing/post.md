# I invented a CVE number to test my tool. It was real.

I've been building a thing that checks whether the claims in a bug report
correspond to anything that exists. Not whether the report is AI-generated —
whether the file it names is in the repository, whether the function is
declared, whether the version was ever tagged.

To test it end to end I wrote a deliberately fabricated security report against
one of my own projects. Fake file, fake function, fake commit hash, and a CVE
number I made up on the spot: `CVE-2026-45871`.

The tool came back and told me the CVE was real. It's a Linux kernel TPM bug —
"st33zp24: Fix missing cleanup on get_burstcount() error." I had invented a
number and hit a live one.

Every other fabricated claim in that report was correctly flagged. The CVE, the
one claim a triager would most want challenged, came back green and read like
corroboration. My tool was asking "does this identifier exist" when the question
that mattered was "does it have anything to do with this project."

That's now the only open issue on the project, and it's a better bug than
anything I found by staring at the code.

## Why I built this

Maintainers are getting buried in bug reports and security disclosures that read
fluently and reference code that doesn't exist. The reports are cheap to
generate and expensive to triage, and that asymmetry is the whole problem: a
maintainer has to read carefully to find out there was nothing there.

The useful property of these reports is that they hallucinate *plausible
identifiers*. `Curl_hpack_decode()` instead of `Curl_hpack_decode_header()`.
`lib/vtls/openssl_helper.c`, which sounds exactly like a file curl would have.
Identifiers are mechanically checkable. You don't need a model to ask whether a
symbol is declared — you need a parser and a git repository.

So: extract every checkable claim from the report, resolve each one against the
repo at the revision the report says it affects, and report what didn't resolve.
No judgement about who wrote it, no score, no auto-close.

## The measurement

Documentation is a convenient corpus and a bad one — it drifts, it's full of
illustrative examples, it references other projects. Security advisories are the
actual workload.

curl publishes all 206 of its advisories in OSV format, each with the prose
writeup and the exact affected version. Every one is human-written, every one was
accepted as valid, and every claim in them was true of the release it describes.
So any claim that fails to resolve is a false positive — with one controllable
exception, which is checking an advisory against the wrong revision. The harness
runs each advisory twice, once against HEAD and once against the release it
actually names.

| Corpus | Claims | Not found | Unexplained |
|---|---|---|---|
| curl advisories, at the affected release | 129 | 9.3% | **3.1%** |
| curl advisories, at HEAD | 124 | 12.1% | **5.6%** |
| curl `docs/` (4,449 files) | 1,165 | 40.7% | **32.0%** |

"Unexplained" means a miss carrying no hint. A miss that says *"no file by that
name, but `lib/hpack.c` exists"* is useful to everyone. A bare miss on an honest
report is what gets a tool uninstalled, so that's the column I care about.

The gap between the two advisory rows is the cost of not telling it which
release you mean. Check a 2019 advisory against today's HEAD and it will
correctly tell you the function is gone, which is true and useless.

## Two bugs worth describing

**Tree-sitter's error recovery is arbitrary, and I was reading declarations off
it.** curl declares every option through a macro:

```c
CURLOPT(CURLOPT_AUTOREFERER, CURLOPTTYPE_LONG, 58),
CURLOPT(CURLOPT_SSL_VERIFYPEER, CURLOPTTYPE_LONG, 64),
```

The C grammar has no rule for a macro-wrapped enumerator, so the parser
error-recovers. Where the recovered ERROR node *ends* is arbitrary: for one
entry it stopped after `CURLOPT(` and the name survived as a real enumerator,
for the other it swallowed `CURLOPT(CURLOPT_AUTOREFERER` whole and the name was
never seen. Identical syntax, 22 lines apart in one enum, opposite answers.

To a maintainer that doesn't read as "the claim was wrong." It reads as "this
tool is broken." I now read enum bodies from their own text instead of trusting
the recovered tree.

**Some names don't exist as text anywhere.** Through curl 7.62, every option was
written like this:

```c
#define CINIT(na, t, nu) CURLOPT_ ## na = t + nu
CINIT(SSL_VERIFYPEER, LONG, 64),
```

`CURLOPT_SSL_VERIFYPEER` appears **zero times** in the header that declares it.
The preprocessor builds it. And my candidate files were chosen by grepping for
the name — so grepping found the docs that mention it and never the header that
declares it. Fixing the parser did nothing until I fixed that too.

Fixing both took the pinned advisory row from 24.0% unexplained to 3.1%. The
four remaining misses are internal functions curl has since renamed or removed.

## What it does not do

It catches *lazy* fabrication. A report that only names real symbols passes
clean, and by design I have no way to distinguish a well-grounded fabrication
from an honest report — the tool refuses to judge authorship, which is the whole
reason a maintainer can run it without poisoning their contributor
relationships.

The 32% on curl's docs is the number I'd push back on if I were reading this.
Documentation is a harsher corpus than reports — it's full of build variables,
other projects' APIs, and illustrative examples — and some of those "misses" are
correct: `CURLOPT_CONNECTIMEOUT` is a typo in curl's own prose for
`CURLOPT_CONNECTTIMEOUT`, and reporting that it resolves to nothing is right. But
I won't pretend that rate would be pleasant on a live issue tracker.

Which is the honest limitation: every number above is a replay. No maintainer has
run this against real inbound traffic, and "does it stay quiet enough on honest
reports that you leave it enabled" is a question I can't answer by myself.

If you maintain something that gets this kind of report, I'd genuinely like to
know what it does on yours.

```yaml
- uses: Dgotlieb/substantiate@c6ae746b882a2454bcb8f2fa5d8587278299f8c3  # v0.1.3
  with:
    report: ${{ github.event.issue.body }}
```

Apache-2.0. Zero dependencies for the default path.
