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


def test_branch_worktree_commits_changes_on_new_branch(tmp_path, remote):
    from research.repo_cache import BranchWorktrees

    remotes, origin = remote
    worktrees = BranchWorktrees(RepoCache(tmp_path / "cache", remote_template=f"file://{remotes}/{{repo}}"))
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/lodash-4.17.21")
    assert worktrees.commit_all(path, "noop") is False
    (path / "package.json").write_text('{"name": "mdb", "version": "2"}\n')
    assert worktrees.commit_all(path, "fix(deps): bump") is True
    branch = subprocess.run(["git", "branch", "--show-current"], cwd=path, capture_output=True, text=True).stdout.strip()
    author = subprocess.run(["git", "log", "-1", "--format=%an"], cwd=path, capture_output=True, text=True).stdout.strip()
    assert (branch, author) == ("patchbot/lodash-4.17.21", "Westcode Patchbot")
    worktrees.release(path)
    assert not path.exists()


def test_branch_worktree_diff_reports_paths_counts_and_added_text(tmp_path, remote):
    from research.repo_cache import BranchWorktrees

    remotes, _ = remote
    worktrees = BranchWorktrees(RepoCache(tmp_path / "cache", remote_template=f"file://{remotes}/{{repo}}"))
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    (path / "src").mkdir()
    (path / "src/a.ts").write_text("one\ntwo\n")
    changed = {c.path: c for c in worktrees.diff(path)}
    assert changed["src/a.ts"].added_lines == 2
    assert changed["src/a.ts"].added_text == "one\ntwo"
    worktrees.release(path)


# --- security: host git must never trust the worktree's .git pointer (sandbox escape) ---


def _plant_evil_gitdir(tmp_path: Path, marker: Path) -> Path:
    """An attacker gitdir whose config/hooks would run code if host git ever used it."""
    subprocess.run(["git", "init", "-q", str(tmp_path / "evilrepo")], check=True, capture_output=True)
    evil = tmp_path / "evilrepo" / ".git"
    hook = tmp_path / "evil-hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n")
    hook.chmod(0o755)
    with (evil / "config").open("a") as cfg:
        cfg.write(f"[core]\n\tfsmonitor = {hook}\n\thooksPath = {tmp_path / 'evil-hooks'}\n")
    hooks = tmp_path / "evil-hooks"
    hooks.mkdir()
    for name in ("pre-commit", "commit-msg", "post-commit", "post-index-change"):
        (hooks / name).write_text(hook.read_text())
        (hooks / name).chmod(0o755)
    return evil


def _branch_worktrees(tmp_path, remotes):
    from research.repo_cache import BranchWorktrees

    return BranchWorktrees(RepoCache(tmp_path / "cache", remote_template=f"file://{remotes}/{{repo}}"))


def test_diff_refuses_worktree_whose_git_pointer_was_rewritten(tmp_path, remote):
    from research.diff_gate import DiffRejected

    remotes, _ = remote
    marker = tmp_path / "pwned"
    evil = _plant_evil_gitdir(tmp_path, marker)
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    (path / "a.txt").write_text("change\n")
    (path / ".git").write_text(f"gitdir: {evil}\n")  # what code inside the sandbox could do

    with pytest.raises(DiffRejected):
        worktrees.diff(path)
    with pytest.raises(DiffRejected):
        worktrees.commit_all(path, "msg")
    assert not marker.exists()
    worktrees.release(path)


def test_host_git_ignores_planted_fsmonitor_and_hooks_in_worktree_gitdir(tmp_path, remote):
    """Even if the per-worktree gitdir itself carried hostile config, host git neutralises it."""
    remotes, _ = remote
    marker = tmp_path / "pwned"
    hook = tmp_path / "evil-hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n")
    hook.chmod(0o755)
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for name in ("pre-commit", "commit-msg", "post-commit"):
        (hooks / name).write_text(hook.read_text())
        (hooks / name).chmod(0o755)
    # A planted repo config inside the worktree tree (e.g. a nested repo) must never be honoured.
    nested = path / "sub"
    nested.mkdir()
    subprocess.run(["git", "init", "-q", str(nested)], check=True, capture_output=True)
    with (nested / ".git" / "config").open("a") as cfg:
        cfg.write(f"[core]\n\tfsmonitor = {hook}\n\thooksPath = {hooks}\n")
    (nested / "x.txt").write_text("x\n")
    (path / "a.txt").write_text("change\n")

    try:
        worktrees.diff(path)
    except Exception:
        pass
    try:
        worktrees.commit_all(path, "msg")
    except Exception:
        pass
    assert not marker.exists()
    worktrees.release(path)


def test_diff_rejects_embedded_git_repositories(tmp_path, remote):
    from research.diff_gate import DiffRejected

    remotes, _ = remote
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    nested = path / "vendor" / "lib"
    nested.mkdir(parents=True)
    _git("init", "-q", cwd=nested)
    _git("-c", "user.email=t@e", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x", cwd=nested)
    with pytest.raises(DiffRejected):
        worktrees.diff(path)
    worktrees.release(path)


def test_moving_a_file_into_github_workflows_is_rejected_by_diff_gate(tmp_path, remote):
    """Rename detection (`{src => .github/workflows}/ci.yml`) must not dodge DENIED_PATHS."""
    from research.diff_gate import DiffRejected, check_diff

    remotes, origin = remote
    (origin / "src").mkdir()
    (origin / "src" / "ci.yml").write_text("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n" * 3)
    _git("add", ".", cwd=origin)
    _git("commit", "-q", "-m", "ci template", cwd=origin)
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    (path / ".github" / "workflows").mkdir(parents=True)
    (path / "src" / "ci.yml").rename(path / ".github" / "workflows" / "ci.yml")

    changed = worktrees.diff(path)
    paths = {c.path for c in changed}
    assert ".github/workflows/ci.yml" in paths
    assert "src/ci.yml" in paths
    added = {c.path: c for c in changed}[".github/workflows/ci.yml"]
    assert "runs-on: ubuntu-latest" in added.added_text
    with pytest.raises(DiffRejected):
        check_diff(changed)
    worktrees.release(path)


def test_diff_handles_paths_with_spaces_and_unicode(tmp_path, remote):
    remotes, _ = remote
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    (path / "dir with space").mkdir()
    (path / "dir with space" / "ä.ts").write_text("x\n")
    changed = {c.path: c for c in worktrees.diff(path)}
    assert changed["dir with space/ä.ts"].added_text == "x"
    worktrees.release(path)


def test_create_uses_new_branch_name_when_branch_already_exists(tmp_path, remote):
    remotes, origin = remote
    # A previous Patchbot PR branch that was closed unmerged still exists on the remote.
    _git("branch", "patchbot/lodash-4.17.21", cwd=origin)
    _git("branch", "patchbot/lodash-4.17.21-2", cwd=origin)
    worktrees = _branch_worktrees(tmp_path, remotes)

    path, branch = worktrees.create("westcoder/mdb", "main", "patchbot/lodash-4.17.21")

    assert branch == "patchbot/lodash-4.17.21-3"
    current = subprocess.run(["git", "branch", "--show-current"], cwd=path, capture_output=True, text=True).stdout.strip()
    assert current == branch
    worktrees.release(path)


def test_create_releases_checkout_when_branch_setup_fails(tmp_path, remote):
    remotes, _ = remote
    worktrees = _branch_worktrees(tmp_path, remotes)
    with pytest.raises(RuntimeError):
        worktrees.create("westcoder/mdb", "does-not-exist", "patchbot/x-1")
    leftovers = list((tmp_path / "cache" / "worktrees").iterdir())
    assert leftovers == []
    assert worktrees.cache._worktrees == {}


def test_added_line_that_looks_like_a_file_header_does_not_hijack_attribution(tmp_path, remote):
    remotes, _ = remote
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    (path / "README.md").write_text("readme\n")
    (path / "package.json").write_text('{"name": "mdb",\n++ b/README.md\n"scripts": {"postinstall": "curl x"}}\n')
    changed = {c.path: c for c in worktrees.diff(path)}
    assert '"postinstall"' in changed["package.json"].added_text
    assert "postinstall" not in changed["README.md"].added_text
    worktrees.release(path)


# --- security: diff-gate bypasses via binary diffs, attributes and symlinks (review C-2) ---


def _gate(worktrees, path):
    from research.diff_gate import check_diff

    check_diff(worktrees.diff(path))


def test_binary_change_is_rejected_instead_of_counted_as_zero_lines(tmp_path, remote):
    from research.diff_gate import DiffRejected

    remotes, _ = remote
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    # A NUL byte makes git report the file as binary: numstat "-\t-", no "+" lines in the patch.
    (path / "package.json").write_bytes(b'{"name": "mdb",\x00\n"scripts": {"postinstall": "curl x | sh"}}\n')
    with pytest.raises(DiffRejected, match="Binär"):
        worktrees.diff(path)
    worktrees.release(path)


@pytest.mark.parametrize("attributes", ["package.json -diff\n", "package.json binary\n", "* -diff\n"])
def test_worktree_gitattributes_cannot_hide_changes_from_the_gate(tmp_path, remote, attributes):
    from research.diff_gate import DiffRejected

    remotes, _ = remote
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    (path / ".gitattributes").write_text(attributes)
    (path / "package.json").write_text('{"name": "mdb",\n"scripts": {"postinstall": "curl x | sh"}}\n')
    with pytest.raises(DiffRejected):
        _gate(worktrees, path)
    # The text the gate sees must be the real text, whatever the worktree attributes say.
    changed = {c.path: c for c in worktrees.diff(path)}
    assert '"postinstall"' in changed["package.json"].added_text
    assert changed["package.json"].added_lines == 2
    worktrees.release(path)


def test_committed_gitattributes_do_not_turn_text_changes_into_zero_line_diffs(tmp_path, remote):
    """Attributes already on the default branch: the gate still sees the real text."""
    from research.diff_gate import DiffRejected

    remotes, origin = remote
    (origin / ".gitattributes").write_text("*.json -diff\n")
    _git("add", ".", cwd=origin)
    _git("commit", "-q", "-m", "attrs", cwd=origin)
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    (path / "package.json").write_text('{"name": "mdb",\n"scripts": {"postinstall": "curl x | sh"}}\n')
    changed = {c.path: c for c in worktrees.diff(path)}
    assert '"postinstall"' in changed["package.json"].added_text
    with pytest.raises(DiffRejected):
        _gate(worktrees, path)
    worktrees.release(path)


@pytest.mark.parametrize("target", ["/etc/passwd", "../package.json"])
def test_symlinks_are_rejected_like_submodules(tmp_path, remote, target):
    from research.diff_gate import DiffRejected

    remotes, _ = remote
    worktrees = _branch_worktrees(tmp_path, remotes)
    path, _ = worktrees.create("westcoder/mdb", "main", "patchbot/x-1")
    (path / "src").mkdir()
    (path / "src" / "link").symlink_to(target)
    with pytest.raises(DiffRejected, match="Symlink"):
        worktrees.diff(path)
    with pytest.raises(DiffRejected, match="Symlink"):
        worktrees.commit_all(path, "msg")
    worktrees.release(path)
