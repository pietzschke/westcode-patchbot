"""Diff gate for Claude-written changes (spec v2.1 §5.5). Enforced outside the sandbox."""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_CHANGED_LINES = 500

DENIED_PATHS = [
    re.compile(p)
    for p in (
        r"^\.github/",
        r"^\.circleci/",
        r"(^|/)deploy/",
        r"(^|/)infra/",
        r"(^|/)k8s/",
        r"(^|/)helm/",
        r"\.tf$",
        r"(^|/)(docker-)?compose[^/]*\.ya?ml$",
        r"(^|/)\.env",
        r"(^|/)\.git/",
        # VCS / package-manager config: changes diff rendering, fetches code or runs code on install.
        r"(^|/)\.gitattributes$",
        r"(^|/)\.gitmodules$",
        r"(^|/)\.npmrc$",
        r"(^|/)\.yarnrc",
        r"(^|/)\.yarn/",
        r"(^|/)\.pnpmfile\.cjs$",
    )
]
SECRET_PATTERNS = [
    re.compile(p)
    for p in (
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"gh[pousr]_[A-Za-z0-9]{36,}",
        r"xox[abprs]-[A-Za-z0-9-]+",
        r"sk-ant-[A-Za-z0-9_-]{10,}",
    )
]
LIFECYCLE_SCRIPT_RE = re.compile(r'"(pre|post)?install"\s*:|"prepare"\s*:|"prepublish"\s*:')


@dataclass(frozen=True)
class ChangedFile:
    path: str
    added_lines: int
    removed_lines: int
    added_text: str


class DiffRejected(Exception):
    pass


def is_denied_path(path: str) -> bool:
    return any(p.search(path) for p in DENIED_PATHS)


def check_diff(files: list[ChangedFile]) -> None:
    if not files:
        raise DiffRejected("Die Änderung ist leer.")
    total = sum(f.added_lines + f.removed_lines for f in files)
    if total > MAX_CHANGED_LINES:
        raise DiffRejected(f"Zu große Änderung ({total} Zeilen, erlaubt sind {MAX_CHANGED_LINES}).")
    for f in files:
        if is_denied_path(f.path):
            raise DiffRejected(f"Geschützte Datei geändert: {f.path}")
        if any(p.search(f.added_text) for p in SECRET_PATTERNS):
            raise DiffRejected(f"Mögliches Secret in {f.path}")
        if f.path.endswith("package.json") and LIFECYCLE_SCRIPT_RE.search(f.added_text):
            raise DiffRejected(f"npm-Lifecycle-Script in {f.path} hinzugefügt")
