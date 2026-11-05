"""Westcode Patchbot host agent: read-only, push-only telemetry reporter.

Collects host inventory with read-only commands and posts it to
``/api/agent/report/``. It contains no code path that changes the host and
never acts on server responses.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
from typing import Any, Callable, Iterable, Tuple
import urllib.request

RunnerCallable = Callable[..., Tuple[int, str, str]]

AGENT_VERSION = "2.0.0"

_APT_INST_RE = re.compile(
    r"^Inst\s+(?P<name>\S+)(?:\s+\[(?P<installed>[^\]]+)\])?\s+\((?P<candidate>\S+)\s+(?P<origin>[^)]+)\)"
)


def default_runner(cmd: list[str], cwd: str | Path | None = None) -> tuple[int, str, str]:
    """Execute a fixed argument vector command without a shell."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return (127, "", str(exc))
    return (proc.returncode, proc.stdout, proc.stderr)


def parse_apt_simulation(sim_output: str) -> list[dict]:
    """Parse `apt-get -s dist-upgrade` output into structured package upgrade records."""
    packages: list[dict] = []
    for raw_line in sim_output.splitlines():
        line = raw_line.strip()
        if not line.startswith("Inst "):
            continue
        match = _APT_INST_RE.match(line)
        if not match:
            continue
        origin = match.group("origin") or ""
        # origin looks like "Ubuntu:24.04/noble-security [amd64]"
        pocket = origin.split()[0].split("/", 1)[1] if "/" in origin.split()[0] else ""
        packages.append(
            {
                "name": match.group("name"),
                "installed_version": match.group("installed") or "",
                "candidate_version": match.group("candidate"),
                "is_security_update": "security" in origin.lower(),
                "source_pocket": pocket,
            }
        )
    return packages


def _parse_os_release(os_release_path: Path) -> tuple[str, str]:
    if not os_release_path.is_file():
        return ("", "")
    distro = ""
    version = ""
    for raw_line in os_release_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        val = val.strip().strip('"').strip("'")
        if key == "ID":
            distro = val
        elif key == "VERSION_ID":
            version = val
    return (distro, version)


DEFAULT_APT_STAMP_PATHS = (
    Path("/var/lib/apt/periodic/update-success-stamp"),
    Path("/var/lib/apt/lists"),
)


def _apt_lists_updated_at(stamp_paths: Iterable[Path]) -> str:
    """Return the mtime of the first existing apt freshness marker as ISO 8601 UTC."""
    for path in stamp_paths:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    return ""


def _installed_packages(runner: RunnerCallable) -> dict[str, str]:
    rc, out, _ = runner(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    if rc != 0:
        return {}
    installed: dict[str, str] = {}
    for line in out.splitlines():
        name, _, version = line.partition("\t")
        if name.strip() and version.strip():
            installed[name.strip()] = version.strip()
    return installed


def _git(runner: RunnerCallable, working_dir: str, *args: str) -> tuple[int, str, str]:
    # safe.directory: /opt checkouts are often owned by a deploy user, the agent runs as root.
    return runner(["git", "-c", f"safe.directory={working_dir}", *args], cwd=working_dir)


def _collect_containers(runner: RunnerCallable) -> list[dict]:
    containers: list[dict] = []
    ps_rc, ps_out, _ = runner(["docker", "ps", "-q"])
    if ps_rc != 0 or not ps_out.strip():
        return containers
    for cid in [c.strip() for c in ps_out.splitlines() if c.strip()]:
        insp_rc, insp_out, _ = runner(["docker", "inspect", cid])
        if insp_rc != 0 or not insp_out.strip():
            continue
        try:
            inspected = json.loads(insp_out)
        except json.JSONDecodeError:
            continue
        if not inspected or not isinstance(inspected, list):
            continue
        item = inspected[0]
        config = item.get("Config") or {}
        labels = config.get("Labels") or {}
        state = item.get("State") or {}
        image_id = item.get("Image", "")

        repo_digests: list[str] = []
        image_created_at = ""
        if image_id:
            img_rc, img_out, _ = runner(["docker", "image", "inspect", image_id])
            if img_rc == 0 and img_out.strip():
                try:
                    img_data = json.loads(img_out)
                except json.JSONDecodeError:
                    img_data = []
                if isinstance(img_data, list) and img_data:
                    repo_digests = list(img_data[0].get("RepoDigests") or [])
                    image_created_at = str(img_data[0].get("Created") or "")

        working_dir = labels.get("com.docker.compose.project.working_dir", "")
        git_clean: bool | None = None
        git_head_sha = ""
        if working_dir:
            status_rc, status_out, _ = _git(runner, working_dir, "status", "--porcelain")
            if status_rc == 0:
                git_clean = status_out.strip() == ""
            head_rc, head_out, _ = _git(runner, working_dir, "rev-parse", "HEAD")
            if head_rc == 0:
                git_head_sha = head_out.strip()

        containers.append(
            {
                "container_id": item.get("Id", cid),
                "name": str(item.get("Name", "")).lstrip("/"),
                "image_tag": config.get("Image", ""),
                "image_id": image_id,
                "repo_digests": repo_digests,
                "image_created_at": image_created_at,
                "oci_title": labels.get("org.opencontainers.image.title", ""),
                "oci_revision": labels.get("org.opencontainers.image.revision", ""),
                "oci_source": labels.get("org.opencontainers.image.source", ""),
                "working_dir": working_dir,
                "compose_service": labels.get("com.docker.compose.service", ""),
                "git_head_sha": git_head_sha,
                "git_clean": git_clean,
                "status": state.get("Status", "running"),
            }
        )
    return containers


def collect_host_inventory(
    runner: RunnerCallable | None = None,
    os_release_path: Path = Path("/etc/os-release"),
    reboot_required_path: Path = Path("/var/run/reboot-required"),
    apt_stamp_paths: Iterable[Path] = DEFAULT_APT_STAMP_PATHS,
) -> dict:
    """Gather OS, kernel, installed + upgradable packages, apt freshness and running containers."""
    active_runner = runner or default_runner
    os_distro, os_version = _parse_os_release(os_release_path)

    uname_rc, uname_out, _ = active_runner(["uname", "-r"])
    kernel_version = uname_out.strip() if uname_rc == 0 else ""

    apt_rc, apt_out, _ = active_runner(["apt-get", "-s", "dist-upgrade"])
    upgrades = {p["name"]: p for p in (parse_apt_simulation(apt_out) if apt_rc == 0 else [])}
    packages: list[dict] = []
    for name, version in sorted(_installed_packages(active_runner).items()):
        upgrade = upgrades.pop(name, None)
        packages.append(
            upgrade
            or {
                "name": name,
                "installed_version": version,
                "candidate_version": "",
                "is_security_update": False,
                "source_pocket": "",
            }
        )
    packages.extend(upgrades.values())  # upgrade candidates not reported by dpkg-query

    return {
        "agent_version": AGENT_VERSION,
        "os_distro": os_distro,
        "os_version": os_version,
        "kernel_version": kernel_version,
        "reboot_required": reboot_required_path.exists(),
        "apt_lists_updated_at": _apt_lists_updated_at(apt_stamp_paths),
        "packages": packages,
        "containers": _collect_containers(active_runner),
    }


def _http_json(
    url: str,
    method: str = "GET",
    token: str = "",
    payload: dict[str, Any] | None = None,
) -> Any:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data: bytes | None = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw.strip() else {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Westcode Patchbot stdlib host agent")
    parser.add_argument(
        "--server-url",
        "--url",
        dest="server_url",
        default=os.environ.get("PATCHBOT_URL")
        or os.environ.get("PATCHBOT_SERVER_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("PATCHBOT_TOKEN")
        or os.environ.get("PATCHBOT_AGENT_TOKEN", ""),
    )
    parser.add_argument(
        "--hostname",
        default=os.environ.get("PATCHBOT_HOSTNAME") or socket.gethostname(),
    )
    parser.add_argument(
        "--collect-json",
        action="store_true",
        help="Collect host inventory and print JSON to stdout without server reporting",
    )
    args = parser.parse_args(argv)
    if args.collect_json:
        inventory = collect_host_inventory(runner=default_runner)
        inventory["hostname"] = args.hostname
        print(json.dumps(inventory))
        return 0

    base = args.server_url.rstrip("/")
    inventory = collect_host_inventory(runner=default_runner)
    inventory["hostname"] = args.hostname
    # Push-only: the response body is deliberately ignored. The agent never
    # receives or executes instructions from the server.
    _http_json(f"{base}/api/agent/report/", method="POST", token=args.token, payload=inventory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
