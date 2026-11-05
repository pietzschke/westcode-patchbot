"""Westcode Patchbot host agent: read-only, push-only telemetry reporter.

Collects host inventory with read-only commands and posts it to
``/api/agent/report/``. It contains no code path that changes the host and
never acts on server responses.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
from typing import Any, Callable, Tuple
import urllib.request

RunnerCallable = Callable[..., Tuple[int, str, str]]

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
        packages.append(
            {
                "name": match.group("name"),
                "installed_version": match.group("installed") or "",
                "candidate_version": match.group("candidate"),
                "is_security_update": "security" in origin.lower(),
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


def collect_host_inventory(
    runner: RunnerCallable | None = None,
    os_release_path: Path = Path("/etc/os-release"),
    reboot_required_path: Path = Path("/var/run/reboot-required"),
) -> dict:
    """Gather OS release info, reboot flag, apt simulation upgrades, and running containers."""
    active_runner = runner or default_runner
    os_distro, os_version = _parse_os_release(os_release_path)
    reboot_required = reboot_required_path.exists()

    apt_rc, apt_out, _ = active_runner(["apt-get", "-s", "dist-upgrade"])
    packages = parse_apt_simulation(apt_out) if apt_rc == 0 else []

    containers: list[dict] = []
    ps_rc, ps_out, _ = active_runner(["docker", "ps", "-q"])
    if ps_rc == 0 and ps_out.strip():
        container_ids = [cid.strip() for cid in ps_out.splitlines() if cid.strip()]
        for cid in container_ids:
            insp_rc, insp_out, _ = active_runner(["docker", "inspect", cid])
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
            if image_id:
                img_rc, img_out, _ = active_runner(["docker", "image", "inspect", image_id])
                if img_rc == 0 and img_out.strip():
                    try:
                        img_data = json.loads(img_out)
                        if isinstance(img_data, list) and img_data:
                            repo_digests = list(img_data[0].get("RepoDigests") or [])
                    except json.JSONDecodeError:
                        repo_digests = []

            working_dir = labels.get("com.docker.compose.project.working_dir", "")
            git_clean: bool | None = None
            if working_dir:
                git_rc, git_out, _ = active_runner(
                    ["git", "status", "--porcelain"],
                    cwd=working_dir,
                )
                if git_rc == 0:
                    git_clean = git_out.strip() == ""

            containers.append(
                {
                    "container_id": item.get("Id", cid),
                    "name": str(item.get("Name", "")).lstrip("/"),
                    "image_tag": config.get("Image", ""),
                    "image_id": image_id,
                    "repo_digests": repo_digests,
                    "oci_title": labels.get("org.opencontainers.image.title", ""),
                    "oci_revision": labels.get("org.opencontainers.image.revision", ""),
                    "working_dir": working_dir,
                    "compose_service": labels.get("com.docker.compose.service", ""),
                    "git_clean": git_clean,
                    "status": state.get("Status", "running"),
                }
            )

    return {
        "os_distro": os_distro,
        "os_version": os_version,
        "reboot_required": reboot_required,
        "packages": packages,
        "containers": containers,
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
