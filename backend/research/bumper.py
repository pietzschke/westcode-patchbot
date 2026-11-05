"""Deterministic dependency bumps (no LLM). Only these may go into a ready (non-draft) PR."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Callable

NPM = {"npm", "yarn", "pnpm", "node-pkg"}
UV = {"uv"}
PIP = {"pip", "pipenv", "python-pkg"}


class BumpFailed(Exception):
    pass


def _default_runner(argv: list[str], cwd=None, timeout=None) -> tuple[int, str, str]:
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout or 600, check=False)
    return proc.returncode, proc.stdout, proc.stderr


class Bumper:
    def __init__(self, runner: Callable[..., tuple[int, str, str]] = _default_runner):
        self.runner = runner

    def _run(self, argv: list[str], worktree: Path) -> None:
        rc, out, err = self.runner(argv, cwd=str(worktree), timeout=600)
        if rc != 0:
            raise BumpFailed((err or out or f"{argv[0]} exited with {rc}").strip()[:1000])

    def bump(self, worktree: Path, ecosystem: str, package: str, version: str) -> list[str]:
        worktree = Path(worktree)
        eco = (ecosystem or "").lower()
        if eco in NPM and (worktree / "package.json").exists():
            # --ignore-scripts: never run package lifecycle scripts on the Patchbot server.
            self._run(["npm", "install", f"{package}@{version}", "--package-lock-only", "--ignore-scripts",
                       "--no-audit", "--no-fund"], worktree)
            return ["package.json", "package-lock.json"]
        if eco in UV and (worktree / "uv.lock").exists():
            self._run(["uv", "lock", "--upgrade-package", f"{package}=={version}"], worktree)
            return ["uv.lock"]
        if eco in PIP:
            return self._bump_requirements(worktree, package, version)
        raise BumpFailed(f"unsupported ecosystem for automatic bumps: {ecosystem}")

    @staticmethod
    def _bump_requirements(worktree: Path, package: str, version: str) -> list[str]:
        pattern = re.compile(rf"^(?P<name>{re.escape(package)})(?P<extras>\[[^\]]*\])?==[^\s#;]+", re.IGNORECASE | re.MULTILINE)
        changed: list[str] = []
        for path in sorted(worktree.glob("requirements*.txt")):
            text = path.read_text(encoding="utf-8")
            new_text, count = pattern.subn(lambda m: f"{m.group('name')}{m.group('extras') or ''}=={version}", text)
            if count:
                path.write_text(new_text, encoding="utf-8")
                changed.append(path.name)
        if not changed:
            raise BumpFailed(f"No pinned requirement for {package} found.")
        return changed
