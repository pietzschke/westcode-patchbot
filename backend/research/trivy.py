"""Trivy runner. A failed or unparsable scan is FAILED — never an empty (clean) result."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from functools import cmp_to_key
from pathlib import Path
from typing import Callable

from triage.versions import compare_versions

ACTIONABLE_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}
DEFAULT_TIMEOUT = 300
# The trivy-db sidecar refreshes every 6 h (upstream publishes every 6 h); 24 h means several missed cycles.
DB_MAX_AGE = timedelta(hours=24)
Runner = Callable[[list[str], int], tuple[int, str, str]]


@dataclass
class TrivyResult:
    status: str
    error: str
    vulnerabilities: list[dict] = field(default_factory=list)


def default_runner(argv: list[str], timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def _pick_fixed(ecosystem: str, installed: str, fixed: str) -> str:
    options = [f.strip() for f in fixed.split(",") if f.strip()]
    upgrades = [o for o in options if not installed or compare_versions(ecosystem, o, installed) > 0]
    pool = upgrades or options
    if not pool:
        return ""
    return min(pool, key=cmp_to_key(lambda a, b: compare_versions(ecosystem, a, b)))


def parse_report(report: dict) -> list[dict]:
    vulns: list[dict] = []
    for result in report.get("Results") or []:
        ecosystem = str(result.get("Type") or "")
        for v in result.get("Vulnerabilities") or []:
            severity = str(v.get("Severity") or "UNKNOWN").upper()
            fixed_raw = str(v.get("FixedVersion") or "")
            status = str(v.get("Status") or ("fixed" if fixed_raw else "")).lower()
            if severity not in ACTIONABLE_SEVERITIES or status != "fixed" or not fixed_raw:
                continue
            installed = str(v.get("InstalledVersion") or "")
            vulns.append(
                {
                    "id": str(v.get("VulnerabilityID") or ""),
                    "package": str(v.get("PkgName") or ""),
                    "installed": installed,
                    "fixed": _pick_fixed(ecosystem, installed, fixed_raw),
                    "severity": severity,
                    "ecosystem": ecosystem,
                    "pkg_class": str(result.get("Class") or ""),
                    "target": str(result.get("Target") or ""),
                    "title": str(v.get("Title") or ""),
                }
            )
    return vulns


def _run(argv: list[str], runner: Runner, timeout: int) -> TrivyResult:
    try:
        rc, out, err = runner(argv, timeout)
    except subprocess.TimeoutExpired:
        return TrivyResult("FAILED", f"Trivy timed out after {timeout}s")
    except OSError as exc:
        return TrivyResult("FAILED", f"Trivy could not be started: {exc}")
    if rc != 0:
        return TrivyResult("FAILED", (err or out or f"exit code {rc}").strip()[:2000])
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        return TrivyResult("FAILED", "Trivy returned invalid JSON")
    return TrivyResult("OK", "", parse_report(report))


_COMMON = ["--scanners", "vuln", "--severity", "MEDIUM,HIGH,CRITICAL", "--skip-db-update", "--format", "json", "--quiet"]


def run_trivy_fs(path: Path, *, runner: Runner = default_runner, timeout: int = DEFAULT_TIMEOUT) -> TrivyResult:
    return _run(["trivy", "fs", *_COMMON, str(path)], runner, timeout)


def run_trivy_image(image_ref: str, *, runner: Runner = default_runner, timeout: int = DEFAULT_TIMEOUT) -> TrivyResult:
    # --image-src remote: pull layers from the registry; the Patchbot server needs no Docker daemon.
    return _run(["trivy", "image", *_COMMON, "--image-src", "remote", image_ref], runner, timeout)


def update_trivy_db(*, runner: Runner = default_runner, timeout: int = DEFAULT_TIMEOUT) -> TrivyResult:
    try:
        rc, out, err = runner(["trivy", "image", "--download-db-only", "--quiet"], timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return TrivyResult("FAILED", f"Trivy DB update failed: {exc}")
    return TrivyResult("OK", "") if rc == 0 else TrivyResult("FAILED", (err or out).strip()[:2000])


def trivy_cache_dir() -> Path:
    """Trivy's own cache location: $TRIVY_CACHE_DIR, else ~/.cache/trivy (the shared worker-cache volume)."""
    return Path(os.environ.get("TRIVY_CACHE_DIR") or Path.home() / ".cache" / "trivy")


def check_trivy_db(*, cache_dir: Path | None = None, now: datetime | None = None,
                   max_age: timedelta = DB_MAX_AGE) -> TrivyResult:
    """Scans run with --skip-db-update, so a stale or missing DB must be reported, never scanned against
    silently (spec §5.1, Anti-Goal 6). Reads ``db/metadata.json`` (``UpdatedAt``) written by Trivy."""
    now = now or datetime.now(dt_timezone.utc)
    path = (cache_dir or trivy_cache_dir()) / "db" / "metadata.json"
    try:
        meta = json.loads(path.read_text())
        updated = datetime.fromisoformat(str(meta["UpdatedAt"]))
    except FileNotFoundError:
        return TrivyResult("FAILED", f"Trivy-DB fehlt ({path} nicht gefunden).")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return TrivyResult("FAILED", f"Trivy-DB-Metadaten nicht lesbar ({path}): {exc}")
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=dt_timezone.utc)
    age = now - updated
    if age > max_age:
        hours = int(age.total_seconds() // 3600)
        return TrivyResult("FAILED", f"Trivy-DB ist {hours} h alt (Stand {updated:%d.%m.%Y %H:%M} UTC); "
                                     "die Aktualisierung (trivy-db) schlägt offenbar fehl.")
    return TrivyResult("OK", "")


class TrivyScanner:
    """Adapter used by the scan pipeline."""

    def __init__(self, runner: Runner = default_runner, timeout: int = DEFAULT_TIMEOUT, cache_dir: Path | None = None):
        self.runner = runner
        self.timeout = timeout
        self.cache_dir = cache_dir

    def db_status(self, now: datetime | None = None) -> TrivyResult:
        return check_trivy_db(cache_dir=self.cache_dir, now=now)

    def scan_repo(self, full_name: str, path: Path) -> TrivyResult:
        return run_trivy_fs(path, runner=self.runner, timeout=self.timeout)

    def scan_image(self, image_ref: str) -> TrivyResult:
        return run_trivy_image(image_ref, runner=self.runner, timeout=self.timeout)
