"""Ecosystem-aware version comparison (dpkg, PEP 440, semver-like)."""

from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Iterable

from packaging.version import InvalidVersion, Version

DEB_ECOSYSTEMS = {"deb", "debian", "ubuntu", "dpkg"}
PYPI_ECOSYSTEMS = {"pypi", "pip", "python", "python-pkg", "poetry", "pipenv", "uv"}


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


# --- dpkg (Debian policy §5.6.12) -------------------------------------------
def _order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_deb(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, revision = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, upstream, revision


def compare_deb(a: str, b: str) -> int:
    ea, ua, ra = _split_deb(a.strip())
    eb, ub, rb = _split_deb(b.strip())
    if ea != eb:
        return _sign(ea - eb)
    return _sign(_verrevcmp(ua, ub)) or _sign(_verrevcmp(ra, rb))


# --- semver-like ------------------------------------------------------------
def _ident_cmp(x: str, y: str) -> int:
    if x.isdigit() and y.isdigit():
        return _sign(int(x) - int(y))
    if x.isdigit():
        return -1
    if y.isdigit():
        return 1
    return _sign((x > y) - (x < y))


def compare_semverish(a: str, b: str) -> int:
    if not a.strip() or not b.strip():
        # A missing version is never newer than a known one (``"" > "1.0.0"`` in identifier order).
        return _sign(bool(a.strip()) - bool(b.strip()))

    def parts(v: str):
        v = v.strip().lstrip("vV").split("+", 1)[0]
        core, _, pre = v.partition("-")
        return re.split(r"[.]", core), [p for p in pre.split(".") if p] if pre else []

    (ca, pa), (cb, pb) = parts(a), parts(b)
    for x, y in zip(ca + ["0"] * (len(cb) - len(ca)), cb + ["0"] * (len(ca) - len(cb))):
        c = _ident_cmp(x, y)
        if c:
            return c
    if not pa and not pb:
        return 0
    if not pa:
        return 1  # release > prerelease
    if not pb:
        return -1
    for x, y in zip(pa, pb):
        c = _ident_cmp(x, y)
        if c:
            return c
    return _sign(len(pa) - len(pb))


def compare_versions(ecosystem: str, a: str, b: str) -> int:
    eco = (ecosystem or "").lower()
    if eco in DEB_ECOSYSTEMS:
        return compare_deb(a, b)
    if eco in PYPI_ECOSYSTEMS:
        try:
            va, vb = Version(a), Version(b)
            return _sign((va > vb) - (va < vb))
        except InvalidVersion:
            pass
    return compare_semverish(a, b)


def max_version(ecosystem: str, versions: Iterable[str]) -> str:
    candidates = [v for v in versions if v]
    if not candidates:
        return ""
    return max(candidates, key=cmp_to_key(lambda x, y: compare_versions(ecosystem, x, y)))
