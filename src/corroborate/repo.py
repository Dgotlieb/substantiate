"""Read-only access to the repository a report is making claims about.

Everything resolves at an explicit ref. A report that names a file which exists
on ``main`` but not at the released tag it claims to affect is making a false
claim, and checking against the working tree would hide that.
"""

from __future__ import annotations

import functools
import os
import subprocess
from pathlib import Path


class RepoError(RuntimeError):
    pass


class Repo:
    def __init__(self, path: str | os.PathLike = ".", ref: str = "HEAD") -> None:
        self.path = Path(path).resolve()
        if not self.path.is_dir():
            raise RepoError(f"not a directory: {self.path}")
        self.ref = ref
        self.is_git = self._git_ok(["rev-parse", "--git-dir"])
        if self.is_git and not self._git_ok(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"]):
            raise RepoError(f"ref not found in repository: {ref}")

    # -- git plumbing ----------------------------------------------------

    def _git(self, args: list[str]) -> str:
        proc = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RepoError(proc.stderr.strip() or f"git {' '.join(args)} failed")
        return proc.stdout

    def _git_ok(self, args: list[str]) -> bool:
        proc = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0

    # -- queries ---------------------------------------------------------

    @functools.cached_property
    def files(self) -> list[str]:
        """Every tracked path at ``ref`` (or every file on disk, outside git)."""
        if self.is_git:
            return [p for p in self._git(["ls-tree", "-r", "--name-only", self.ref]).splitlines() if p]
        out: list[str] = []
        for root, dirs, names in os.walk(self.path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
            for n in names:
                out.append(str(Path(root, n).relative_to(self.path)))
        return out

    @functools.cached_property
    def _by_basename(self) -> dict[str, list[str]]:
        index: dict[str, list[str]] = {}
        for p in self.files:
            index.setdefault(os.path.basename(p).lower(), []).append(p)
        return index

    def exists(self, path: str) -> bool:
        norm = path.lstrip("./")
        if norm in self.files:
            return True
        # Reports routinely omit or add a leading component ("src/http2.c" vs
        # "lib/http2.c" vs "http2.c"). Treat an unambiguous suffix match as a hit.
        return any(f == norm or f.endswith("/" + norm) for f in self.files)

    def resolve(self, path: str) -> str | None:
        norm = path.lstrip("./")
        for f in self.files:
            if f == norm or f.endswith("/" + norm):
                return f
        return None

    def same_basename(self, path: str) -> list[str]:
        """Other locations holding a file of this name -- the usual explanation
        for a genuine report that cites a moved or renamed file."""
        return self._by_basename.get(os.path.basename(path).lower(), [])

    def read(self, path: str) -> str | None:
        resolved = self.resolve(path)
        if resolved is None:
            return None
        try:
            if self.is_git:
                return self._git(["show", f"{self.ref}:{resolved}"])
            return (self.path / resolved).read_text(errors="replace")
        except (RepoError, OSError, UnicodeDecodeError):
            return None

    def line_count(self, path: str) -> int | None:
        content = self.read(path)
        return None if content is None else len(content.splitlines())

    @functools.cached_property
    def tags(self) -> list[str]:
        if not self.is_git:
            return []
        return [t for t in self._git(["tag", "--list"]).splitlines() if t]

    def find_tag(self, version: str) -> str | None:
        """Match a bare version against the tag naming scheme the project uses.

        Projects spell the same release ``8.9.0``, ``v8.9.0``, ``curl-8_9_0`` or
        ``release-8.9.0``; a report should not be penalised for picking one.
        """
        v = version.lstrip("vV")
        underscored = v.replace(".", "_")
        candidates = {v, f"v{v}", f"V{v}", underscored, f"v{underscored}"}
        for tag in self.tags:
            if tag in candidates:
                return tag
            stripped = tag.lstrip("vV")
            if stripped == v or stripped.endswith("-" + v) or stripped.endswith("_" + underscored):
                return tag
            if tag.endswith(underscored) or tag.endswith(v):
                return tag
        return None

    def has_commit(self, sha: str) -> bool:
        if not self.is_git:
            return False
        return self._git_ok(["cat-file", "-e", f"{sha}^{{commit}}"])
