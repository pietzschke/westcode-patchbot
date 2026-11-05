"""Deterministic evidence for the triage policy gate (spec v2.1 §5.4).

Claude may *claim* a dependency is dev-only or unused; the policy gate only
accepts such a claim when this module confirms it from lockfiles or source.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__", "site-packages", ".next"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".php", ".go", ".rb"}
NPM_ECOSYSTEMS = {"npm", "yarn", "pnpm", "node-pkg"}
PYTHON_ECOSYSTEMS = {"pip", "pipenv", "poetry", "uv", "pypi", "python-pkg"}
MAX_FILE_BYTES = 1_000_000


def _npm_dev_only(checkout: Path, package: str) -> bool:
    lock = checkout / "package-lock.json"
    if not lock.is_file():
        return False
    try:
        packages = json.loads(lock.read_text(encoding="utf-8")).get("packages") or {}
    except (OSError, json.JSONDecodeError):
        return False
    entries = [meta for key, meta in packages.items() if key.endswith(f"node_modules/{package}")]
    return bool(entries) and all(bool(meta.get("dev")) for meta in entries)


def _poetry_dev_only(checkout: Path, package: str) -> bool:
    lock = checkout / "poetry.lock"
    if not lock.is_file():
        return False
    try:
        data = tomllib.loads(lock.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    entries = [p for p in data.get("package", []) if str(p.get("name", "")).lower() == package.lower()]
    return bool(entries) and all(p.get("category") == "dev" for p in entries)


def _uv_dev_only(checkout: Path, package: str) -> bool:
    lock = checkout / "uv.lock"
    if not lock.is_file():
        return False
    try:
        data = tomllib.loads(lock.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    name = package.lower()
    for pkg in data.get("package", []):
        source = pkg.get("source") or {}
        if not (source.get("editable") or source.get("virtual")):
            continue
        runtime = {str(d.get("name", "")).lower() for d in pkg.get("dependencies", [])}
        dev = {str(d.get("name", "")).lower() for group in (pkg.get("dev-dependencies") or {}).values() for d in group}
        return name in dev and name not in runtime
    return False


def is_dev_only(checkout: Path | None, ecosystem: str, package: str) -> bool:
    if checkout is None:
        return False
    eco = (ecosystem or "").lower()
    if eco in NPM_ECOSYSTEMS:
        return _npm_dev_only(checkout, package)
    if eco in PYTHON_ECOSYSTEMS:
        return _poetry_dev_only(checkout, package) or _uv_dev_only(checkout, package)
    return False


def _pattern(ecosystem: str, package: str, module_hint: str | None) -> re.Pattern:
    eco = (ecosystem or "").lower()
    if eco in NPM_ECOSYSTEMS:
        pkg = re.escape(package)
        return re.compile(rf"""(?:from\s+|require\(\s*|import\s*\(\s*|import\s+)['"]{pkg}(?:/[^'"]*)?['"]""")
    if eco in PYTHON_ECOSYSTEMS:
        module = re.escape(module_hint or package.lower().replace("-", "_"))
        return re.compile(rf"^\s*(?:import|from)\s+{module}\b")
    return re.compile(rf"\b{re.escape(package)}\b")


def find_call_sites(
    checkout: Path | None, ecosystem: str, package: str, *, module_hint: str | None = None, limit: int = 10_000
) -> list[dict]:
    if checkout is None or not checkout.is_dir():
        return []
    pattern = _pattern(ecosystem, package, module_hint)
    sites: list[dict] = []
    for path in sorted(checkout.rglob("*")):
        rel = path.relative_to(checkout)
        if any(part in SKIP_DIRS for part in rel.parts) or path.suffix not in SOURCE_SUFFIXES or not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, text in enumerate(lines, start=1):
            if pattern.search(text):
                sites.append({"path": rel.as_posix(), "line": number, "text": text.strip()[:200]})
                if len(sites) >= limit:
                    return sites
    return sites


def call_site_hits(checkout: Path | None, ecosystem: str, package: str, *, module_hint: str | None = None) -> int:
    return len(find_call_sites(checkout, ecosystem, package, module_hint=module_hint))
