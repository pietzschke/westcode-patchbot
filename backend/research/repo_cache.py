"""Bare mirror cache + throwaway worktrees for scanning default branches.

Never uses a developer's local checkout. Credentials (GitHub App installation
token) are passed to git via environment-based config, not via argv.

Worktrees may later be mounted into the code-patching sandbox, so host-side git
never discovers the repository through the worktree's ``.git`` file: every call
uses the gitdir recorded at creation time, with hooks/fsmonitor disabled and no
system/global config, and the ``.git`` pointer is verified before staging.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import stat
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NamedTuple

from inventory.github_app import CheckoutInfo
from research.diff_gate import DiffRejected

Runner = Callable[..., tuple[int, str, str]]

# Neutralise config that makes git execute programs (fsmonitor, hooks) or recurse into nested repositories.
SAFE_GIT_CONFIG = (
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.untrackedCache=false",
    "-c", "submodule.recurse=false",
    "-c", "protocol.file.allow=never",
)


class WorktreeTampered(DiffRejected):
    """The worktree's ``.git`` pointer changed after creation (e.g. rewritten from inside the sandbox)."""


@dataclass(frozen=True)
class _Worktree:
    mirror: Path
    git_dir: Path  # <mirror>/worktrees/<name>, recorded when Patchbot created the worktree
    pointer: bytes  # original content of <worktree>/.git


def _default_runner(argv: list[str], cwd=None, env=None) -> tuple[int, str, str]:
    proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=600)
    return proc.returncode, proc.stdout, proc.stderr


class RepoCache:
    def __init__(
        self,
        cache_dir: Path,
        *,
        org: str = "westcoder",
        remote_template: str = "https://github.com/{repo}.git",
        token_provider: Callable[[], str] | None = None,
        runner: Runner = _default_runner,
    ):
        self.cache_dir = Path(cache_dir)
        self.org = org
        self.remote_template = remote_template
        self.token_provider = token_provider
        self.runner = runner
        self._repo_re = re.compile(rf"^{re.escape(org)}/[A-Za-z0-9_.-]+$")
        self._worktrees: dict[str, _Worktree] = {}

    def _validate(self, repo: str) -> str:
        if not self._repo_re.match(repo) or ".." in repo:
            raise ValueError(f"Refusing repository name {repo!r}.")
        return repo.split("/", 1)[1]

    def _env(self) -> dict[str, str]:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        if self.token_provider and self.remote_template.startswith("https://github.com/"):
            basic = base64.b64encode(f"x-access-token:{self.token_provider()}".encode()).decode()
            env.update({
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
            })
        return env

    def _git(self, *args: str, cwd=None) -> str:
        rc, out, err = self.runner(["git", *args], cwd=cwd, env=self._env())
        if rc != 0:
            raise RuntimeError(f"git {args[0]} failed: {err.strip()[:500]}")
        return out

    # --- worktree git: never discovered through the worktree's own ``.git`` file ---------------------------

    def _local_env(self) -> dict[str, str]:
        """Environment for local git calls on worktrees: no inherited GIT_* overrides, no system/global config."""
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
        })
        return env

    def _record_worktree(self, mirror: Path, worktree: Path) -> _Worktree:
        """Read the gitdir pointer of a *fresh* worktree (before any untrusted code ran in it) and pin it."""
        pointer = (worktree / ".git").read_bytes()
        text = pointer.decode("utf-8", errors="strict").strip()
        if not text.startswith("gitdir: "):
            raise RuntimeError(f"Unexpected .git pointer in {worktree}.")
        git_dir = (worktree / text[len("gitdir: "):]).resolve()
        if git_dir.parent != (mirror / "worktrees").resolve():
            raise RuntimeError(f"Worktree gitdir {git_dir} is not inside mirror {mirror}.")
        return _Worktree(mirror=mirror, git_dir=git_dir, pointer=pointer)

    def _meta(self, worktree: Path) -> _Worktree:
        meta = self._worktrees.get(str(worktree))
        if meta is None:
            raise RuntimeError(f"Unknown worktree {worktree}.")
        return meta

    def run_worktree_git(self, worktree: Path, *args: str) -> tuple[int, str, str]:
        """git on a Patchbot worktree with the gitdir recorded at creation time and risky config disabled."""
        meta = self._meta(Path(worktree))
        argv = ["git", f"--git-dir={meta.git_dir}", f"--work-tree={worktree}", *SAFE_GIT_CONFIG, *args]
        return self.runner(argv, cwd=str(worktree), env=self._local_env())

    def worktree_git(self, worktree: Path, *args: str) -> str:
        rc, out, err = self.run_worktree_git(worktree, *args)
        if rc != 0:
            raise RuntimeError(f"git {args[0]} failed: {err.strip()[:500]}")
        return out

    def verify_worktree(self, worktree: Path) -> None:
        """Reject a worktree whose ``.git`` pointer differs from what Patchbot recorded (sandbox tampering)."""
        meta = self._meta(Path(worktree))
        dotgit = Path(worktree) / ".git"
        try:
            unchanged = stat.S_ISREG(dotgit.lstat().st_mode) and dotgit.read_bytes() == meta.pointer
        except OSError:
            unchanged = False
        if not unchanged:
            raise WorktreeTampered(f"Die .git-Datei des Worktrees wurde verändert: {worktree}")

    def checkout(self, repo: str) -> CheckoutInfo:
        name = self._validate(repo)
        mirror = self.cache_dir / "mirrors" / f"{name}.git"
        if mirror.exists():
            self._git("--git-dir", str(mirror), "fetch", "--prune", "origin")
        else:
            mirror.parent.mkdir(parents=True, exist_ok=True)
            self._git("clone", "--mirror", "--quiet", self.remote_template.format(repo=repo), str(mirror))
        worktree = self.cache_dir / "worktrees" / f"{name}-{uuid.uuid4().hex[:8]}"
        worktree.parent.mkdir(parents=True, exist_ok=True)
        self._git("--git-dir", str(mirror), "worktree", "add", "--detach", "--quiet", str(worktree), "HEAD")
        try:
            self._worktrees[str(worktree)] = self._record_worktree(mirror, worktree)
            sha = self.worktree_git(worktree, "rev-parse", "HEAD").strip()
        except Exception:
            self._discard(mirror, worktree)
            raise
        return CheckoutInfo(path=worktree, commit_sha=sha)

    def _discard(self, mirror: Path, worktree: Path) -> None:
        # Never run git inside the (possibly tampered) worktree: delete it, then let the mirror prune its admin dir.
        self._worktrees.pop(str(worktree), None)
        shutil.rmtree(worktree, ignore_errors=True)
        self.runner(["git", "--git-dir", str(mirror), *SAFE_GIT_CONFIG, "worktree", "prune"], env=self._local_env())

    def release(self, info: CheckoutInfo) -> None:
        meta = self._worktrees.get(str(info.path))
        if meta is not None:
            self._discard(meta.mirror, Path(info.path))
        else:
            shutil.rmtree(info.path, ignore_errors=True)

    def as_checkout_provider(self) -> Callable:
        """Adapter for RestGitHubClient(checkout_provider=...)."""
        return lambda repo, client: self.checkout(repo)


class BranchCheckout(NamedTuple):
    path: Path
    branch: str  # the branch actually created (may carry a -2, -3, ... suffix)


_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _unquote_git_path(text: str) -> str:
    """Undo git's C-style path quoting (``"a\\tb"``, octal escapes) as used in patch headers."""
    if not (len(text) >= 2 and text[0] == '"' and text[-1] == '"'):
        return text
    body, out, i = text[1:-1], bytearray(), 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt, octal = body[i + 1], body[i + 1:i + 4]
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
                continue
            if len(octal) == 3 and all(c in "01234567" for c in octal):
                out.append(int(octal, 8) & 0xFF)
                i += 4
                continue
        out += ch.encode("utf-8")
        i += 1
    return out.decode("utf-8", errors="replace")


class BranchWorktrees:
    """Worktrees on new ``patchbot/*`` branches for preparing fix PRs (used by the PR engine)."""

    AUTHOR = ("Westcode Patchbot", "patchbot@westcode.de")
    MAX_BRANCH_ATTEMPTS = 50

    def __init__(self, cache: RepoCache):
        self.cache = cache

    def _free_branch_name(self, path: Path, branch: str) -> str:
        """Patchbot never force-pushes: if the branch exists (e.g. an earlier PR closed unmerged), use -2, -3, ..."""
        for attempt in range(1, self.MAX_BRANCH_ATTEMPTS + 1):
            candidate = branch if attempt == 1 else f"{branch}-{attempt}"
            rc, _, _ = self.cache.run_worktree_git(path, "rev-parse", "--verify", "--quiet", f"refs/heads/{candidate}")
            if rc != 0:
                return candidate
        raise RuntimeError(f"No free branch name for {branch} after {self.MAX_BRANCH_ATTEMPTS} attempts.")

    def create(self, repo: str, base: str, branch: str) -> BranchCheckout:
        if base.startswith("-") or branch.startswith("-"):
            raise ValueError("Refusing option-like branch names.")
        info = self.cache.checkout(repo)  # fresh detached worktree of the default branch
        try:
            if base:
                self.cache.worktree_git(info.path, "checkout", "--quiet", "--detach", base)
            used = self._free_branch_name(info.path, branch)
            self.cache.worktree_git(info.path, "checkout", "--quiet", "-b", used)
        except Exception:
            self.cache.release(info)
            raise
        return BranchCheckout(info.path, used)

    def _stage(self, path: Path) -> None:
        """Verify the worktree pointer, stage everything and refuse submodule / symlink changes."""
        self.cache.verify_worktree(path)
        self.cache.worktree_git(path, "add", "--all")
        raw = self.cache.worktree_git(path, "diff", "--cached", "--raw", "--no-renames", "--no-ext-diff", "-z")
        fields = raw.split("\0")
        for i in range(0, len(fields) - 1, 2):
            modes = fields[i].lstrip(":").split(" ")[:2]
            if "160000" in modes:
                raise DiffRejected(f"Eingebettetes Git-Repository/Submodul geändert: {fields[i + 1]}")
            if "120000" in modes:
                # The gate only sees the link target as one line of text; what the link exposes stays invisible.
                raise DiffRejected(f"Symlink geändert: {fields[i + 1]}")

    def _diff_git(self, path: Path, *args: str) -> str:
        """``git diff`` that reads no gitattributes: neither the worktree's (writable from the sandbox) nor the
        committed ones may mark files ``binary``/``-diff`` and thereby hide added text from the gate."""
        empty_tree = self.cache.worktree_git(path, "hash-object", "-t", "tree", os.devnull).strip()
        return self.cache.worktree_git(path, f"--attr-source={empty_tree}", *args)

    def commit_all(self, path: Path, message: str) -> bool:
        self._stage(path)
        if not self.cache.worktree_git(path, "status", "--porcelain", "--ignore-submodules=all").strip():
            return False
        name, email = self.AUTHOR
        self.cache.worktree_git(path, "-c", f"user.name={name}", "-c", f"user.email={email}",
                                "commit", "--quiet", "--no-verify", "-m", message)
        return True

    def diff(self, path: Path):
        """Staged changes as ChangedFile entries (paths, line counts and added text) for the diff gate.

        ``--no-renames`` is essential: with rename detection a move into ``.github/workflows/`` is reported as
        ``{src => .github/workflows}/ci.yml`` and would dodge the denied-path check.

        Binary changes (numstat ``-``) are refused: git prints no ``+`` lines for them, so line limit, secret and
        lifecycle-script checks would see an empty change.
        """
        from research.diff_gate import ChangedFile

        self._stage(path)
        counts: dict[str, tuple[int, int]] = {}
        numstat = self._diff_git(path, "diff", "--cached", "--numstat", "--no-renames", "--no-ext-diff",
                                 "--no-textconv", "-z")
        for record in numstat.split("\0"):
            if not record:
                continue
            added, removed, name = record.split("\t", 2)
            if not (added.isdigit() and removed.isdigit()):
                raise DiffRejected(f"Binärdatei geändert: {name}")
            counts[name] = (int(added), int(removed))
        added_text: dict[str, list[str]] = {name: [] for name in counts}
        patch = self._diff_git(path, "-c", "core.quotePath=false", "diff", "--cached", "-U0", "--no-color",
                               "--no-renames", "--no-ext-diff", "--no-textconv", "--text")
        # Only "+++" lines in a file header name the file; inside hunks a line "+++ b/x" is added content.
        current, in_header = None, False
        for line in patch.split("\n"):
            if line.startswith("diff --git "):
                current, in_header = None, True
            elif in_header and line.startswith("+++ "):
                # git appends a TAB to header names containing spaces
                target = _unquote_git_path(line[4:].removesuffix("\t"))
                current = target[2:] if target.startswith("b/") else None
            elif line.startswith("@@"):
                in_header = False
            elif not in_header and line.startswith("+") and current in added_text:
                added_text[current].append(line[1:])
        return [ChangedFile(name, a, r, "\n".join(added_text[name])) for name, (a, r) in counts.items()]

    def release(self, path: Path) -> None:
        self.cache.release(CheckoutInfo(path=Path(path), commit_sha=""))
