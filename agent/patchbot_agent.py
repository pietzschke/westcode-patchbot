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
import pwd
import re
import socket
import stat
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


# --- git checkouts under /opt ------------------------------------------------------------------------------
# The agent runs as root, but /opt/<app> checkouts belong to a deploy user who controls .git/config. Running
# git there as root would execute that user's core.fsmonitor / filter.*.clean / ... as root. Therefore HEAD is
# read by parsing files (no git at all), and `git status` only runs as the checkout's owner.

_HEX_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REF_RE = re.compile(r"^refs/[A-Za-z0-9._/+-]+$")
_SMALL_FILE = 4096
_PACKED_REFS_LIMIT = 16 * 1024 * 1024
GIT_STATUS_ARGV = [
    "git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "--no-optional-locks",
    "status", "--porcelain",
]


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _read_checkout_file(path: str, root: str, limit: int = _SMALL_FILE) -> str | None:
    """Read a regular file that (after resolving symlinks) lies inside ``root``; None otherwise.

    O_NONBLOCK + the S_ISREG check keep a planted FIFO/device from blocking or being read as root.
    """
    real = os.path.realpath(path)
    if not _inside(real, root):
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(real, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            chunk = os.read(fd, min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def _resolve_git_dir(root: str) -> str | None:
    dotgit = os.path.join(root, ".git")
    real = os.path.realpath(dotgit)
    if not _inside(real, root):
        return None
    if os.path.isdir(real):
        return real
    content = _read_checkout_file(dotgit, root)
    if not content or not content.startswith("gitdir:"):
        return None
    git_dir = os.path.realpath(os.path.join(root, content[len("gitdir:"):].strip()))
    # A gitdir file pointing outside the checkout is not followed (it could point anywhere on the host).
    if not _inside(git_dir, root) or not os.path.isdir(git_dir):
        return None
    return git_dir


def _packed_ref(common_dir: str, ref: str, root: str) -> str:
    packed = _read_checkout_file(os.path.join(common_dir, "packed-refs"), root, _PACKED_REFS_LIMIT) or ""
    for line in packed.splitlines():
        if not line or line[0] in "#^":
            continue
        sha, _, name = line.partition(" ")
        if name.strip() == ref and _HEX_SHA_RE.match(sha):
            return sha
    return ""


def read_git_head(working_dir: str) -> str:
    """HEAD commit of a checkout without executing git: .git/HEAD -> loose ref or packed-refs. "" if unknown."""
    root = os.path.realpath(working_dir)
    git_dir = _resolve_git_dir(root)
    if git_dir is None:
        return ""
    common_dir = git_dir
    commondir = _read_checkout_file(os.path.join(git_dir, "commondir"), root)
    if commondir and commondir.strip():
        common_dir = os.path.realpath(os.path.join(git_dir, commondir.strip()))
        if not _inside(common_dir, root):
            return ""
    value = (_read_checkout_file(os.path.join(git_dir, "HEAD"), root) or "").strip()
    for _ in range(5):  # symbolic refs may chain; bounded
        if _HEX_SHA_RE.match(value):
            return value
        if not value.startswith("ref:"):
            return ""
        ref = value[len("ref:"):].strip()
        if not _REF_RE.match(ref) or ".." in ref.split("/"):
            return ""
        loose = _read_checkout_file(os.path.join(common_dir, ref), root)
        if loose is None:
            return _packed_ref(common_dir, ref, root)
        value = loose.strip()
    return ""


def _dir_owner(path: str) -> tuple[int, int, str] | None:
    try:
        st = os.stat(path)
        return (st.st_uid, st.st_gid, pwd.getpwuid(st.st_uid).pw_name)
    except (OSError, KeyError):
        return None


def _git_clean(runner: RunnerCallable, working_dir: str) -> bool | None:
    """`git status` as the checkout's owner (runuser, util-linux), so hostile repo config can at most act as the
    user who already controls it. Root-owned or unknown-owner checkouts are not inspected (None)."""
    owner = _dir_owner(working_dir)
    if owner is None or owner[0] == 0:
        return None
    rc, out, _ = runner(["runuser", "-u", owner[2], "--", *GIT_STATUS_ARGV], cwd=working_dir)
    if rc != 0:
        return None
    return out.strip() == ""


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
        if working_dir and os.path.isabs(working_dir):
            git_clean = _git_clean(runner, working_dir)
            git_head_sha = read_git_head(working_dir)

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
