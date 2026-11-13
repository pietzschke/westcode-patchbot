"""Scan output handed from ``research`` to ``triage`` (one candidate per finding key)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Vuln:
    id: str
    severity: str
    fixed_version: str


@dataclass
class Candidate:
    project: Any
    layer: str
    target_ref: str
    ecosystem: str
    package_name: str
    current_version: str
    vulns: list[Vuln] = field(default_factory=list)
    repository: Any = None
    host: Any = None
    image_ref: str = ""
