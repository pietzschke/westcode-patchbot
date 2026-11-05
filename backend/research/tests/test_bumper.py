import pytest

from research.bumper import Bumper, BumpFailed


class Runner:
    def __init__(self, rc=0):
        self.rc = rc
        self.calls = []

    def __call__(self, argv, cwd=None, timeout=None):
        self.calls.append((argv, cwd))
        return (self.rc, "", "ERESOLVE unable to resolve" if self.rc else "")


def test_npm_bump_updates_lockfile_without_lifecycle_scripts(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    runner = Runner()
    Bumper(runner=runner).bump(tmp_path, "npm", "lodash", "4.17.21")
    argv, cwd = runner.calls[0]
    assert argv[:3] == ["npm", "install", "lodash@4.17.21"]
    assert "--package-lock-only" in argv and "--ignore-scripts" in argv
    assert cwd == str(tmp_path)


def test_npm_failure_raises(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    with pytest.raises(BumpFailed, match="ERESOLVE"):
        Bumper(runner=Runner(rc=1)).bump(tmp_path, "npm", "lodash", "4.17.21")


def test_uv_bump(tmp_path):
    (tmp_path / "uv.lock").write_text("")
    runner = Runner()
    Bumper(runner=runner).bump(tmp_path, "uv", "django", "5.2.8")
    assert runner.calls[0][0] == ["uv", "lock", "--upgrade-package", "django==5.2.8"]


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
