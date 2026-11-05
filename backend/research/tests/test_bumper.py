import os
from pathlib import Path

import pytest

from research.bumper import Bumper, BumpFailed


class Runner:
    def __init__(self, rc=0, on_call=None):
        self.rc = rc
        self.calls = []
        self.on_call = on_call

    def __call__(self, argv, cwd=None, timeout=None, env=None):
        self.calls.append((argv, cwd))
        self.envs = getattr(self, "envs", []) + [env]
        if self.on_call:
            self.on_call(argv, cwd, env)
        return (self.rc, "", "ERESOLVE unable to resolve" if self.rc else "")


def test_npm_bump_updates_lockfile_without_lifecycle_scripts(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    runner = Runner()
    Bumper(runner=runner).bump(tmp_path, "npm", "lodash", "4.17.21")
    argv, cwd = runner.calls[0]
    assert argv[:2] == ["npm", "install"]
    assert argv[-2:] == ["--", "lodash@4.17.21"]
    assert "--package-lock-only" in argv and "--ignore-scripts" in argv
    assert cwd == str(tmp_path)


def test_npm_failure_raises(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    with pytest.raises(BumpFailed, match="ERESOLVE"):
        Bumper(runner=Runner(rc=1)).bump(tmp_path, "npm", "lodash", "4.17.21")


def test_uv_bump(tmp_path):
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\nversion = "1.0"\n')
    runner = Runner()
    Bumper(runner=runner).bump(tmp_path, "uv", "django", "5.2.8")
    assert runner.calls[0][0] == ["uv", "lock", "--no-build", "--upgrade-package=django==5.2.8"]


def test_requirements_pin_is_rewritten_in_place(tmp_path):
    (tmp_path / "requirements.txt").write_text("Django==5.2.1  # web\nrequests>=2.31\n")
    changed = Bumper(runner=Runner()).bump(tmp_path, "pip", "django", "5.2.8")
    assert changed == ["requirements.txt"]
    assert (tmp_path / "requirements.txt").read_text() == "Django==5.2.8  # web\nrequests>=2.31\n"


def test_requirements_without_pin_cannot_be_bumped(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.31\n")
    with pytest.raises(BumpFailed):
        Bumper(runner=Runner()).bump(tmp_path, "pip", "django", "5.2.8")


def test_unsupported_ecosystem_raises(tmp_path):
    with pytest.raises(BumpFailed, match="unsupported"):
        Bumper(runner=Runner()).bump(tmp_path, "gomod", "golang.org/x/net", "0.23.0")


@pytest.mark.parametrize(("ecosystem", "lockfile"), [("yarn", "yarn.lock"), ("pnpm", "pnpm-lock.yaml")])
def test_yarn_and_pnpm_are_not_bumped_with_npm(tmp_path, ecosystem, lockfile):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / lockfile).write_text("")
    runner = Runner()
    with pytest.raises(BumpFailed, match="unsupported"):
        Bumper(runner=runner).bump(tmp_path, ecosystem, "lodash", "4.17.21")
    assert runner.calls == []
    assert not (tmp_path / "package-lock.json").exists()


def test_npm_without_package_lock_is_unsupported(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    runner = Runner()
    with pytest.raises(BumpFailed, match="unsupported"):
        Bumper(runner=runner).bump(tmp_path, "npm", "lodash", "4.17.21")
    assert runner.calls == []


# --- security: npm/uv run on the worker against untrusted repository content (review C-1) ---

SECRETS = {"ANTHROPIC_API_KEY": "sk-ant-secret", "SLACK_BOT_TOKEN": "xoxb-secret", "POSTGRES_PASSWORD": "pw",
           "DJANGO_SECRET_KEY": "dj", "NOTION_API_KEY": "nt", "UV_INDEX_URL": "https://evil", "npm_config_git": "/x"}


def _npm_repo(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    return tmp_path


@pytest.mark.parametrize("ecosystem", ["npm", "uv"])
def test_tools_get_a_minimal_environment_without_worker_secrets(tmp_path, monkeypatch, ecosystem):
    for key, value in SECRETS.items():
        monkeypatch.setenv(key, value)
    _npm_repo(tmp_path)
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\nversion = "1.0"\n')
    seen = {}

    def on_call(argv, cwd, env):
        seen["home_exists"] = Path(env["HOME"]).is_dir()
        if ecosystem == "npm":
            seen["userconfig"] = Path(env["npm_config_userconfig"]).read_text()
            seen["globalconfig"] = Path(env["npm_config_globalconfig"]).read_text()

    runner = Runner(on_call=on_call)
    Bumper(runner=runner).bump(tmp_path, ecosystem, "lodash" if ecosystem == "npm" else "django", "4.17.21")
    env = runner.envs[0]
    assert env is not None
    assert not set(SECRETS) & set(env)
    assert all(value not in env.values() for value in SECRETS.values())
    assert "PATH" in env and env["TMPDIR"] == env["HOME"]
    assert seen["home_exists"] and not Path(env["HOME"]).exists()  # throwaway home, removed afterwards
    if ecosystem == "npm":
        assert seen["userconfig"] == "" and seen["globalconfig"] == ""


def test_worktree_npmrc_is_hidden_from_npm_and_restored(tmp_path):
    _npm_repo(tmp_path)
    (tmp_path / ".npmrc").write_text("git=./evil.sh\n//registry.npmjs.org/:_authToken=${ANTHROPIC_API_KEY}\n")
    seen = {}
    runner = Runner(on_call=lambda argv, cwd, env: seen.update(present=os.path.lexists(Path(cwd) / ".npmrc")))
    Bumper(runner=runner).bump(tmp_path, "npm", "lodash", "4.17.21")
    assert seen["present"] is False
    assert (tmp_path / ".npmrc").read_text().startswith("git=./evil.sh")


def test_worktree_npmrc_is_restored_when_npm_fails(tmp_path):
    _npm_repo(tmp_path)
    (tmp_path / ".npmrc").write_text("save-exact=true\n")
    with pytest.raises(BumpFailed):
        Bumper(runner=Runner(rc=1)).bump(tmp_path, "npm", "lodash", "4.17.21")
    assert (tmp_path / ".npmrc").read_text() == "save-exact=true\n"


@pytest.mark.parametrize(("package", "version"), [
    ("--registry=https://evil", "1.0.0"), ("lodash", "--registry=https://evil"), ("lodash", "file:../../etc"),
    ("lodash", "git+https://evil/x.git"), ("../x", "1.0.0"), ("lodash", ""), ("", "1.0.0"), ("a b", "1.0"),
])
@pytest.mark.parametrize("ecosystem", ["npm", "uv", "pip"])
def test_option_like_or_non_registry_specs_are_refused(tmp_path, ecosystem, package, version):
    _npm_repo(tmp_path)
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\nversion = "1.0"\n')
    (tmp_path / "requirements.txt").write_text("lodash==1.0\n")
    runner = Runner()
    with pytest.raises(BumpFailed):
        Bumper(runner=runner).bump(tmp_path, ecosystem, package, version)
    assert runner.calls == []


def test_scoped_npm_packages_and_pep440_versions_are_accepted(tmp_path):
    _npm_repo(tmp_path)
    runner = Runner()
    Bumper(runner=runner).bump(tmp_path, "npm", "@angular/core", "20.3.1-rc.0")
    assert runner.calls[0][0][-1] == "@angular/core@20.3.1-rc.0"
    (tmp_path / "requirements.txt").write_text("Django==5.2.1\n")
    Bumper(runner=runner).bump(tmp_path, "pip", "django", "1!5.2.8+local")


@pytest.mark.parametrize("pyproject", [
    '[project]\nname = "app"\ndynamic = ["version"]\n',  # dynamic metadata = uv builds the project (runs setup.py)
    '[build-system]\nrequires = ["setuptools"]\n',  # legacy project without static [project] metadata
])
def test_uv_refuses_projects_whose_metadata_needs_a_build(tmp_path, pyproject):
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text(pyproject)
    runner = Runner()
    with pytest.raises(BumpFailed):
        Bumper(runner=runner).bump(tmp_path, "uv", "django", "5.2.8")
    assert runner.calls == []


def test_uv_refuses_workspace_members_with_dynamic_metadata(tmp_path):
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "1.0"\n[tool.uv.workspace]\nmembers = ["packages/*"]\n')
    (tmp_path / "packages" / "ok").mkdir(parents=True)
    (tmp_path / "packages" / "ok" / "pyproject.toml").write_text('[project]\nname = "ok"\nversion = "1"\n')
    (tmp_path / "packages" / "evil").mkdir()
    (tmp_path / "packages" / "evil" / "pyproject.toml").write_text('[project]\nname = "evil"\ndynamic = ["version"]\n')
    runner = Runner()
    with pytest.raises(BumpFailed):
        Bumper(runner=runner).bump(tmp_path, "uv", "django", "5.2.8")
    assert runner.calls == []


@pytest.mark.parametrize("name", ["package.json", "package-lock.json"])
def test_npm_refuses_symlinked_manifests(tmp_path, name):
    outside = tmp_path / "outside"
    outside.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    _npm_repo(repo)
    (repo / name).unlink()
    (outside / name).write_text("{}")
    (repo / name).symlink_to(outside / name)
    runner = Runner()
    with pytest.raises(BumpFailed):
        Bumper(runner=runner).bump(repo, "npm", "lodash", "4.17.21")
    assert runner.calls == []


def test_uv_refuses_symlinked_lockfile(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text('[project]\nname = "app"\nversion = "1.0"\n')
    (tmp_path / "uv.lock").write_text("")
    (repo / "uv.lock").symlink_to(tmp_path / "uv.lock")
    runner = Runner()
    with pytest.raises(BumpFailed):
        Bumper(runner=runner).bump(repo, "uv", "django", "5.2.8")
    assert runner.calls == []


def test_symlinked_requirements_file_outside_worktree_is_never_rewritten(tmp_path):
    victim = tmp_path / "victim-requirements.txt"
    victim.write_text("Django==5.2.1\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("Django==5.2.1\n")
    (repo / "requirements-prod.txt").symlink_to(victim)
    with pytest.raises(BumpFailed):
        Bumper(runner=Runner()).bump(repo, "pip", "django", "5.2.8")
    assert victim.read_text() == "Django==5.2.1\n"
