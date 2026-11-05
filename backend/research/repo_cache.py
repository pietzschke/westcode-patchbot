"""Bare mirror cache + throwaway worktrees for scanning default branches.

Never uses a developer's local checkout. Credentials (GitHub App installation
token) are passed to git via environment-based config, not via argv.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Callable

from inventory.github_app import CheckoutInfo

Runner = Callable[..., tuple[int, str, str]]


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
        self._mirrors: dict[str, Path] = {}

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
        sha = self._git("rev-parse", "HEAD", cwd=str(worktree)).strip()
        self._mirrors[str(worktree)] = mirror
        return CheckoutInfo(path=worktree, commit_sha=sha)

    def release(self, info: CheckoutInfo) -> None:
        mirror = self._mirrors.pop(str(info.path), None)
        if mirror is not None:
            self.runner(["git", "--git-dir", str(mirror), "worktree", "remove", "--force", str(info.path)], env=self._env())
            self.runner(["git", "--git-dir", str(mirror), "worktree", "prune"], env=self._env())
        shutil.rmtree(info.path, ignore_errors=True)

    def as_checkout_provider(self) -> Callable:
        """Adapter for RestGitHubClient(checkout_provider=...)."""
        return lambda repo, client: self.checkout(repo)


class BranchWorktrees:
    """Worktrees on new ``patchbot/*`` branches for preparing fix PRs (used by the PR engine)."""

    AUTHOR = ("Westcode Patchbot", "patchbot@westcode.de")

    def __init__(self, cache: RepoCache):
        self.cache = cache

    def create(self, repo: str, base: str, branch: str) -> Path:
        info = self.cache.checkout(repo)  # fresh detached worktree of the default branch
        if base:
            self.cache._git("checkout", "--quiet", "--detach", base, cwd=str(info.path))
        self.cache._git("checkout", "--quiet", "-b", branch, cwd=str(info.path))
        return info.path

    def commit_all(self, path: Path, message: str) -> bool:
        self.cache._git("add", "--all", cwd=str(path))
        if not self.cache._git("status", "--porcelain", cwd=str(path)).strip():
            return False
        name, email = self.AUTHOR
        self.cache._git("-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "--quiet", "-m", message,
                        cwd=str(path))
        return True

    def release(self, path: Path) -> None:
        self.cache.release(CheckoutInfo(path=Path(path), commit_sha=""))
