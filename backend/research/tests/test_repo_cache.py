"""Uses a real local git remote (file://) so mirror + worktree handling is exercised end to end."""

import subprocess
from pathlib import Path

import pytest

from research.repo_cache import RepoCache


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def remote(tmp_path):
    origin = tmp_path / "remotes" / "westcoder" / "mdb"
    origin.mkdir(parents=True)
    _git("init", "-q", "-b", "main", cwd=origin)
    _git("config", "user.email", "t@example.com", cwd=origin)
    _git("config", "user.name", "Test", cwd=origin)
    (origin / "package.json").write_text('{"name": "mdb"}\n')
    _git("add", ".", cwd=origin)
    _git("commit", "-q", "-m", "init", cwd=origin)
    return tmp_path / "remotes", origin


def _head(path: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True).stdout.strip()


def test_checkout_creates_fresh_worktree_of_default_branch(tmp_path, remote):
    remotes, origin = remote
    cache = RepoCache(tmp_path / "cache", remote_template=f"file://{remotes}/{{repo}}")

    info = cache.checkout("westcoder/mdb")

    assert (info.path / "package.json").exists()
    assert info.commit_sha == _head(origin)
    cache.release(info)
    assert not info.path.exists()


def test_second_checkout_fetches_new_commits(tmp_path, remote):
    remotes, origin = remote
    cache = RepoCache(tmp_path / "cache", remote_template=f"file://{remotes}/{{repo}}")
    first = cache.checkout("westcoder/mdb")
    cache.release(first)

    (origin / "README.md").write_text("new\n")
    _git("add", ".", cwd=origin)
    _git("commit", "-q", "-m", "second", cwd=origin)

    second = cache.checkout("westcoder/mdb")
    assert second.commit_sha == _head(origin)
    assert (second.path / "README.md").exists()
    cache.release(second)


def test_rejects_repository_names_outside_org(tmp_path):
    cache = RepoCache(tmp_path / "cache")
    for bad in ("../etc", "westcoder/../x", "other/mdb", "westcoder/mdb;rm"):
        with pytest.raises(ValueError):
            cache.checkout(bad)
