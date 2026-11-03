from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
from typing import Any, Callable, Tuple
import urllib.error
import urllib.request

RunnerCallable = Callable[..., Tuple[int, str, str]]

ALLOWED_ACTION_TYPES = frozenset({"precheck", "compose_update", "apt_upgrade", "host_reboot"})
COMPOSE_FILENAMES = ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")

_APT_INST_RE = re.compile(
    r"^Inst\s+(?P<name>\S+)(?:\s+\[(?P<installed>[^\]]+)\])?\s+\((?P<candidate>\S+)\s+(?P<origin>[^)]+)\)"
)
_IMAGE_LINE_RE = re.compile(r"^(\s*image:\s*)(\S+)(\s*(?:#.*)?)$", re.MULTILINE)


def default_runner(cmd: list[str], cwd: str | Path | None = None) -> tuple[int, str, str]:
    """Execute a fixed argument vector command without a shell."""
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        check=False,
    )
    return (proc.returncode, proc.stdout, proc.stderr)


def validate_opt_workdir(working_dir: str, allowed_root: Path = Path("/opt")) -> Path:
    """Ensure working_dir resolves to a canonical subdirectory inside allowed_root."""
    root = Path(allowed_root).resolve()
    target = Path(working_dir).resolve()
    try:
        rel = target.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Working directory '{working_dir}' resolves outside allowed root '{root}'"
        ) from exc
    if rel == Path("."):
        raise ValueError(
            f"Working directory '{working_dir}' must be a subdirectory inside allowed root '{root}'"
        )
    return target


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


def _find_compose_file(workdir: Path) -> Path | None:
    for name in COMPOSE_FILENAMES:
        candidate = workdir / name
        if candidate.is_file():
            return candidate
    return None


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


def run_precheck(
    working_dir: str,
    target_image: str,
    runner: RunnerCallable = default_runner,
    allowed_root: Path = Path("/opt"),
) -> dict:
    """Validate `/opt` working directory, compose file existence, and clean git status."""
    workdir = validate_opt_workdir(working_dir, allowed_root=allowed_root)
    compose_file = _find_compose_file(workdir)
    if compose_file is None:
        return {
            "ok": False,
            "git_clean": False,
            "compose_file": "",
            "reason": f"No compose file found in {workdir}",
        }

    git_rc, git_out, git_err = runner(["git", "status", "--porcelain"], cwd=str(workdir))
    if git_rc != 0 or git_out.strip() != "":
        return {
            "ok": False,
            "git_clean": False,
            "compose_file": str(compose_file),
            "reason": "Working directory has uncommitted git changes or dirty tree",
        }

    if not target_image or not target_image.strip():
        return {
            "ok": False,
            "git_clean": True,
            "compose_file": str(compose_file),
            "reason": "target_image must not be empty",
        }

    return {
        "ok": True,
        "git_clean": True,
        "compose_file": str(compose_file),
        "reason": "ok",
    }


def _rewrite_compose_image(content: str, target_image: str) -> str:
    """Update the image reference in compose YAML content while preserving indentation."""
    target_repo = target_image.split(":", 1)[0].split("@", 1)[0]

    def _replace_matching_repo(match: re.Match[str]) -> str:
        current_img = match.group(2)
        current_repo = current_img.split(":", 1)[0].split("@", 1)[0]
        if current_repo == target_repo:
            return f"{match.group(1)}{target_image}{match.group(3)}"
        return match.group(0)

    updated = _IMAGE_LINE_RE.sub(_replace_matching_repo, content)
    if updated != content:
        return updated
    return _IMAGE_LINE_RE.sub(
        lambda m: f"{m.group(1)}{target_image}{m.group(3)}",
        content,
        count=1,
    )


def _poll_health(
    workdir: Path,
    service: str,
    healthcheck_url: str | None,
    runner: RunnerCallable,
    timeout_sec: int,
) -> bool:
    deadline = time.monotonic() + max(timeout_sec, 0)
    while True:
        if healthcheck_url:
            try:
                with urllib.request.urlopen(healthcheck_url, timeout=2) as response:
                    status_code = getattr(response, "status", response.getcode())
                    if 200 <= int(status_code) < 300:
                        return True
            except (urllib.error.URLError, TimeoutError, ValueError, OSError):
                pass
        else:
            rc, out, _ = runner(
                ["docker", "compose", "ps", "--format", "json", service],
                cwd=str(workdir),
            )
            if rc == 0:
                stripped = out.strip()
                if not stripped:
                    return True
                try:
                    first_line = stripped.splitlines()[0]
                    payload = json.loads(first_line)
                    if isinstance(payload, list):
                        payload = payload[0] if payload else {}
                    state = str(payload.get("State", "running")).lower()
                    health = str(payload.get("Health", "")).lower()
                    if state == "running" and health not in {"unhealthy", "starting"}:
                        return True
                except json.JSONDecodeError:
                    return True

        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


def execute_compose_update(
    working_dir: str,
    service: str,
    target_image: str,
    healthcheck_url: str | None,
    runner: RunnerCallable = default_runner,
    allowed_root: Path = Path("/opt"),
    timeout_sec: int = 60,
) -> dict:
    """Update a compose service to target_image, verify health, or roll back automatically."""
    workdir = validate_opt_workdir(working_dir, allowed_root=allowed_root)
    compose_file = _find_compose_file(workdir)
    if compose_file is None:
        raise FileNotFoundError(f"No compose file found in {workdir}")

    precheck = run_precheck(
        working_dir=working_dir,
        target_image=target_image,
        runner=runner,
        allowed_root=allowed_root,
    )
    if not precheck["ok"]:
        return {
            "status": "failed",
            "prev_image_id": "",
            "new_image_id": "",
            "logs": precheck["reason"],
        }

    original_compose = compose_file.read_text(encoding="utf-8")

    _, prev_img_out, _ = runner(
        ["docker", "compose", "images", "-q", service],
        cwd=str(workdir),
    )
    prev_image_id = prev_img_out.strip()

    updated_compose = _rewrite_compose_image(original_compose, target_image)
    compose_file.write_text(updated_compose, encoding="utf-8")

    pull_rc, _, pull_err = runner(["docker", "compose", "pull", service], cwd=str(workdir))
    up_rc, _, up_err = (
        runner(["docker", "compose", "up", "-d", "--remove-orphans", service], cwd=str(workdir))
        if pull_rc == 0
        else (pull_rc, "", pull_err)
    )

    is_healthy = False
    if pull_rc == 0 and up_rc == 0:
        is_healthy = _poll_health(
            workdir=workdir,
            service=service,
            healthcheck_url=healthcheck_url,
            runner=runner,
            timeout_sec=timeout_sec,
        )

    if is_healthy:
        _, new_img_out, _ = runner(
            ["docker", "compose", "images", "-q", service],
            cwd=str(workdir),
        )
        return {
            "status": "succeeded",
            "prev_image_id": prev_image_id,
            "new_image_id": new_img_out.strip(),
            "logs": "",
        }

    _, logs_out, logs_err = runner(
        ["docker", "compose", "logs", "--tail", "100", service],
        cwd=str(workdir),
    )
    combined_logs = "\n".join(
        part for part in (pull_err.strip(), up_err.strip(), logs_out.strip(), logs_err.strip()) if part
    )

    compose_file.write_text(original_compose, encoding="utf-8")
    rb_rc, _, _ = runner(
        ["docker", "compose", "up", "-d", "--remove-orphans"],
        cwd=str(workdir),
    )
    status = "rolled_back" if rb_rc == 0 else "failed"
    return {
        "status": status,
        "prev_image_id": prev_image_id,
        "new_image_id": "",
        "logs": combined_logs,
    }


def dispatch_agent_job(
    job: dict[str, Any],
    runner: RunnerCallable | None = None,
    allowed_root: Path = Path("/opt"),
) -> dict[str, Any]:
    """Dispatch a single queued control-plane job using a fixed action enum."""
    active_runner = runner or default_runner
    action_type = job.get("action_type", "")
    if action_type not in ALLOWED_ACTION_TYPES:
        raise ValueError(f"Unsupported action_type: {action_type!r}")

    payload = job.get("payload") or {}

    if action_type == "precheck":
        return run_precheck(
            working_dir=str(payload["working_dir"]),
            target_image=str(payload["target_image"]),
            runner=active_runner,
            allowed_root=allowed_root,
        )

    if action_type == "compose_update":
        return execute_compose_update(
            working_dir=str(payload["working_dir"]),
            service=str(payload["service"]),
            target_image=str(payload["target_image"]),
            healthcheck_url=payload.get("healthcheck_url"),
            runner=active_runner,
            allowed_root=allowed_root,
            timeout_sec=int(payload.get("timeout_sec", 60)),
        )

    if action_type == "apt_upgrade":
        upd_rc, upd_out, upd_err = active_runner(["apt-get", "update", "-q"])
        if upd_rc != 0:
            return {"status": "failed", "logs": (upd_out + "\n" + upd_err).strip()}
        upg_rc, upg_out, upg_err = active_runner(
            [
                "apt-get",
                "-y",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "dist-upgrade",
            ]
        )
        return {
            "status": "succeeded" if upg_rc == 0 else "failed",
            "logs": (upg_out + "\n" + upg_err).strip(),
        }

    if action_type == "host_reboot":
        rb_rc, rb_out, rb_err = active_runner(
            ["shutdown", "-r", "+1", "Westcode Patchbot scheduled reboot"]
        )
        return {
            "status": "succeeded" if rb_rc == 0 else "failed",
            "logs": (rb_out + "\n" + rb_err).strip(),
        }

    raise ValueError(f"Unsupported action_type: {action_type!r}")


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
        "--allowed-root",
        default=os.environ.get("PATCHBOT_ALLOWED_ROOT", "/opt"),
    )
    args = parser.parse_args(argv)
    base = args.server_url.rstrip("/")
    allowed_root = Path(args.allowed_root)

    inventory = collect_host_inventory(runner=default_runner)
    inventory["hostname"] = args.hostname
    _http_json(f"{base}/api/agent/report/", method="POST", token=args.token, payload=inventory)

    next_job = _http_json(f"{base}/api/agent/jobs/next/", method="GET", token=args.token)
    job_id = next_job.get("id") if isinstance(next_job, dict) else None
    if job_id:
        result = dispatch_agent_job(next_job, runner=default_runner, allowed_root=allowed_root)
        _http_json(
            f"{base}/api/agent/jobs/{job_id}/result/",
            method="POST",
            token=args.token,
            payload=result,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
