"""Builds a small, deterministic git repository for the test suite.

Shaped like a C project with a released history, because that is the shape most
often on the receiving end of fabricated vulnerability reports.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

HTTP2_C = """\
#include "http2.h"

/* Session setup for the HTTP/2 transport. */
CURLcode Curl_http2_setup(struct connectdata *conn)
{
  return CURLE_OK;
}

static int on_frame_recv(nghttp2_session *session)
{
  return 0;
}

CURLcode Curl_http2_done(struct Curl_easy *data, bool premature)
{
  (void)premature;
  return CURLE_OK;
}

/* Historical note: memory released by Curl_ghost_alloc() used to be logged
 * here, and Curl_ghost_mentioned() is described in the old design docs. */
CURLcode Curl_http2_reset(struct Curl_easy *data)
{
  Curl_called_only(data);
  return Curl_http2_done(data, FALSE);
}
"""

HPACK_C = """\
#include "hpack.h"

/* Header decompression state. */
int Curl_hpack_decode_header(struct hpack_ctx *ctx, const unsigned char *buf,
                             size_t len)
{
  if(!ctx || !buf)
    return -1;
  return (int)len;
}

void Curl_hpack_cleanup(struct hpack_ctx *ctx)
{
  (void)ctx;
}
"""

# Enum constants, in the two shapes a real C project writes them. curl declares
# every one of its options through a macro, which no regex can tell apart from a
# call site passing the same name as an argument -- so this fixture carries both
# the plain and the macro-wrapped form.
OPTIONS_H = """\
#ifndef OPTIONS_H
#define OPTIONS_H

#define FIXTURE_OPT(na, t, nu) na = ((t) + (nu))

typedef enum {
  FIXTURE_OPT_VERIFYPEER = 64,
  FIXTURE_OPT_TIMEOUT = 65,
  FIXTURE_OPT(FIXTURE_OPT_MAXCONNECTS, 0, 66),
} fixture_option;

#endif
"""

TOOL_MAIN_C = """\
#include "tool_main.h"

int main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;
  return 0;
}
"""


SESSION_PY = '''\
"""A small Python module, so the fixture is not C-only.

The fixture repository being pure C is why an entire class of false findings --
dotted attribute calls in Python documentation -- went unnoticed until the
benchmark was pointed at urllib3.
"""

import logging

logger = logging.getLogger(__name__)


class Session:
    def connect(self, host):
        return host

    def close(self):
        logger.setLevel(logging.DEBUG)


def open_session(host):
    return Session()
'''


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def build(root: Path | None = None) -> Path:
    """Create the fixture repository and return its path."""
    root = root or Path(tempfile.mkdtemp(prefix="substantiate-fixture-"))
    (root / "lib").mkdir(parents=True, exist_ok=True)
    (root / "src").mkdir(parents=True, exist_ok=True)

    # Padded so a mid-file line reference is meaningful to test against.
    padding = "\n".join(f"/* line {i} */" for i in range(1, 60))
    (root / "lib" / "http2.c").write_text(HTTP2_C + "\n" + padding + "\n")
    (root / "lib" / "hpack.c").write_text(HPACK_C)
    (root / "lib" / "options.h").write_text(OPTIONS_H)
    (root / "lib" / "http2.h").write_text("#ifndef HTTP2_H\n#define HTTP2_H\n#endif\n")
    (root / "src" / "tool_main.c").write_text(TOOL_MAIN_C)
    (root / "lib" / "session.py").write_text(SESSION_PY)
    (root / "README.md").write_text("# fixture project\n")

    _git(root, "init", "-q")
    _git(root, "config", "user.email", "fixture@example.invalid")
    _git(root, "config", "user.name", "Fixture")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "initial")
    for tag in ("v8.11.0", "v8.12.0", "v8.12.1"):
        _git(root, "tag", tag)
    return root


def head_sha(root: Path) -> str:
    out = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()
