"""Deterministic dependency bumps (no LLM). Only these may go into a ready (non-draft) PR.

npm and uv run on the worker against an untrusted repository, so they get a minimal environment
(no worker secrets for ``${VAR}`` interpolation in a ``.npmrc``), a throwaway HOME, empty npm
user/global config, the worktree's own ``.npmrc`` hidden for the duration of the call, and
``uv lock --no-build`` on projects whose metadata uv can read without running a build backend.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

# Only npm with a package-lock.json: yarn.lock / pnpm-lock.yaml would stay untouched by
# `npm install --package-lock-only` (plus a stray package-lock.json) → a PR that fixes nothing.
NPM = {"npm"}
UV = {"uv"}
PIP = {"pip", "pipenv", "python-pkg"}

# Registry package names / versions only: no leading "-" (option injection), no "file:", "git+https://",
# paths or URLs (npm would install from there instead of the registry).
NPM_NAME_RE = re.compile(r"^(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$")
PY_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+!_-]*$")

# Non-secret settings the tools may inherit from the worker (caches, proxy, CA bundle, locale).
ENV_PASSTHROUGH = (
    "PATH", "LANG", "LC_ALL", "TZ",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
    "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "UV_PYTHON_DOWNLOADS", "npm_config_cache",
)
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"


class BumpFailed(Exception):
    pass


def _default_runner(argv: list[str], cwd=None, timeout=None, env=None) -> tuple[int, str, str]:
    proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout or 600,
                          check=False)
    return proc.returncode, proc.stdout, proc.stderr


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _confined_regular_file(worktree: Path, path: Path) -> None:
    """Refuse symlinks / special files and anything resolving outside the worktree (no writes through links)."""
    if not _is_regular_file(path) or not path.resolve().is_relative_to(worktree.resolve()):
        raise BumpFailed(f"{path.relative_to(worktree).as_posix()} ist keine reguläre Datei im Repository.")


def _static_project_metadata(pyproject: Path, label: str) -> dict:
    """uv builds a project (running setup.py / its build backend) when its metadata is dynamic or missing."""
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BumpFailed(f"{label} nicht lesbar: {exc}") from exc
    project = data.get("project")
    workspace = ((data.get("tool") or {}).get("uv") or {}).get("workspace")
    if project is None and workspace is None:
        raise BumpFailed(f"{label} hat keine statischen [project]-Metadaten.")
    if project is not None and (not isinstance(project, dict) or project.get("dynamic")):
        raise BumpFailed(f"{label} nutzt dynamische Metadaten (würde einen Build im Worker auslösen).")
    return data


class Bumper:
    def __init__(self, runner: Callable[..., tuple[int, str, str]] = _default_runner):
        self.runner = runner

    @staticmethod
    @contextmanager
    def _sandbox_env() -> Iterator[dict[str, str]]:
        """Minimal environment with a throwaway HOME/TMPDIR and empty npm user/global config."""
        home = Path(tempfile.mkdtemp(prefix="patchbot-bump-"))
        try:
            # npm refuses to load the same file as user and global config ("double-loading config").
            user_rc, global_rc = home / "user-npmrc", home / "global-npmrc"
            user_rc.write_text("")
            global_rc.write_text("")
            env = {key: os.environ[key] for key in ENV_PASSTHROUGH if key in os.environ}
            env.setdefault("PATH", DEFAULT_PATH)
            env.update({
                "HOME": str(home),
                "TMPDIR": str(home),
                "npm_config_userconfig": str(user_rc),
                "npm_config_globalconfig": str(global_rc),
                "npm_config_update_notifier": "false",
                "UV_NO_BUILD": "1",
            })
            yield env
        finally:
            shutil.rmtree(home, ignore_errors=True)

    @staticmethod
    @contextmanager
    def _hidden_npmrc(worktree: Path, stash: Path) -> Iterator[None]:
        """npm always reads ``<project>/.npmrc`` (git=, registry, ${ENV} auth); move it out while npm runs."""
        npmrc = worktree / ".npmrc"
        if not os.path.lexists(npmrc):
            yield
            return
        parked = stash / "project-npmrc"
        shutil.move(str(npmrc), str(parked))
        try:
            yield
        finally:
            if os.path.lexists(npmrc):  # never expected; do not let npm's output win over the repo file
                if npmrc.is_dir() and not npmrc.is_symlink():
                    shutil.rmtree(npmrc)
                else:
                    npmrc.unlink()
            shutil.move(str(parked), str(npmrc))

    def _run(self, argv: list[str], worktree: Path, env: dict[str, str]) -> None:
        rc, out, err = self.runner(argv, cwd=str(worktree), timeout=600, env=env)
        if rc != 0:
            raise BumpFailed((err or out or f"{argv[0]} exited with {rc}").strip()[:1000])

    @staticmethod
    def _validate(eco: str, package: str, version: str) -> None:
        name_re = NPM_NAME_RE if eco in NPM else PY_NAME_RE
        if not isinstance(package, str) or not name_re.match(package):
            raise BumpFailed(f"Ungültiger Paketname für automatischen Bump: {package!r}")
        if not isinstance(version, str) or not VERSION_RE.match(version):
            raise BumpFailed(f"Ungültige Version für automatischen Bump: {version!r}")

    def bump(self, worktree: Path, ecosystem: str, package: str, version: str) -> list[str]:
        worktree = Path(worktree)
        eco = (ecosystem or "").lower()
        if eco in NPM and os.path.lexists(worktree / "package.json") and os.path.lexists(worktree / "package-lock.json"):
            self._validate(eco, package, version)
            for name in ("package.json", "package-lock.json"):
                _confined_regular_file(worktree, worktree / name)
            with self._sandbox_env() as env, self._hidden_npmrc(worktree, Path(env["HOME"])):
                # --ignore-scripts: never run package lifecycle scripts on the Patchbot server.
                self._run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                           "--", f"{package}@{version}"], worktree, env)
            return ["package.json", "package-lock.json"]
        if eco in UV and os.path.lexists(worktree / "uv.lock"):
            self._validate(eco, package, version)
            self._check_uv_project(worktree)
            with self._sandbox_env() as env:
                self._run(["uv", "lock", "--no-build", f"--upgrade-package={package}=={version}"], worktree, env)
            return ["uv.lock"]
        if eco in PIP:
            self._validate(eco, package, version)
            return self._bump_requirements(worktree, package, version)
        raise BumpFailed(f"unsupported ecosystem or lockfile for automatic bumps: {ecosystem}")

    @staticmethod
    def _check_uv_project(worktree: Path) -> None:
        """``--no-build`` covers dependencies, not the project/workspace members whose metadata uv needs."""
        _confined_regular_file(worktree, worktree / "uv.lock")
        pyproject = worktree / "pyproject.toml"
        _confined_regular_file(worktree, pyproject)
        data = _static_project_metadata(pyproject, "pyproject.toml")
        workspace = ((data.get("tool") or {}).get("uv") or {}).get("workspace") or {}
        excluded = {p for pattern in workspace.get("exclude", []) for p in worktree.glob(str(pattern))}
        for pattern in workspace.get("members", []):
            for member in worktree.glob(str(pattern)):
                if member in excluded or not member.is_dir():
                    continue
                member_pyproject = member / "pyproject.toml"
                label = member_pyproject.relative_to(worktree).as_posix()
                if member.is_symlink() or not member.resolve().is_relative_to(worktree.resolve()):
                    raise BumpFailed(f"Workspace-Mitglied {label} liegt außerhalb des Repositories.")
                _confined_regular_file(worktree, member_pyproject)
                _static_project_metadata(member_pyproject, label)

    @staticmethod
    def _bump_requirements(worktree: Path, package: str, version: str) -> list[str]:
        pattern = re.compile(rf"^(?P<name>{re.escape(package)})(?P<extras>\[[^\]]*\])?==[^\s#;]+", re.IGNORECASE | re.MULTILINE)
        paths = sorted(worktree.glob("requirements*.txt"))
        for path in paths:  # check all before writing any: never write through a symlink or outside the worktree
            _confined_regular_file(worktree, path)
        changed: list[str] = []
        for path in paths:
            text = path.read_text(encoding="utf-8")
            new_text, count = pattern.subn(lambda m: f"{m.group('name')}{m.group('extras') or ''}=={version}", text)
            if count:
                path.write_text(new_text, encoding="utf-8")
                changed.append(path.name)
        if not changed:
            raise BumpFailed(f"No pinned requirement for {package} found.")
        return changed
