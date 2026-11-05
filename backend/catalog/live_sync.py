import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from catalog.correlator import rebuild_service_groups
from catalog.renovate_sync import parse_renovate_pr
from fleet.infra_sync import sync_infra_hosts
from fleet.models import Host

WESTCODE_SERVICE_DEPLOYMENTS: list[dict[str, Any]] = [
    {
        "slug": "westcode-hub",
        "repo": "westcoder/westcode-hub",
        "local_dir": "westcode-hub",
        "hosts": ["service-westcode-de"],
        "working_dir": "/opt/hub",
        "compose_service": "hub-backend",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/westcode-hub",
        "is_ecr": True,
    },
    {
        "slug": "service-center",
        "repo": "westcoder/service-center",
        "local_dir": "service-center",
        "hosts": ["service-westcode-de", "c2-westcode-network"],
        "working_dir": "/opt/service-center",
        "compose_service": "service-center",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/service-center",
        "is_ecr": True,
    },
    {
        "slug": "ack-desk",
        "repo": "westcoder/ack-desk",
        "local_dir": "ack-desk",
        "hosts": ["desk-ackermann-ib-de"],
        "working_dir": "/opt/ack-desk",
        "compose_service": "ack-desk",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/ack-desk",
        "is_ecr": True,
    },
    {
        "slug": "wyze-agent",
        "repo": "westcoder/wyze-agent",
        "local_dir": "wyze-agent",
        "hosts": ["c2-westcode-network"],
        "working_dir": "/opt/wyze-agent",
        "compose_service": "wyze-agent",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/wyze-agent",
        "is_ecr": True,
    },
    {
        "slug": "projectory",
        "repo": "westcoder/projectory",
        "local_dir": "projectory",
        "hosts": ["p-westcode-de"],
        "working_dir": "/opt/projectory",
        "compose_service": "projectory",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/projectory",
        "is_ecr": True,
    },
    {
        "slug": "materialdatenbank",
        "repo": "westcoder/materialdatenbank",
        "local_dir": "materialdatenbank",
        "hosts": ["mdb-westcode-de"],
        "working_dir": "/opt/materialdatenbank",
        "compose_service": "materialdatenbank",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/materialdatenbank",
        "is_ecr": True,
    },
    {
        "slug": "masteroil",
        "repo": "westcoder/masteroil",
        "local_dir": "masteroil",
        "hosts": ["masteroil-westcode-network"],
        "working_dir": "/opt/masteroil",
        "compose_service": "masteroil",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/masteroil",
        "is_ecr": True,
    },
    {
        "slug": "brockhaus",
        "repo": "westcoder/brockhaus",
        "local_dir": "brockhaus",
        "hosts": ["brockhaus-westcode-network", "dev-brockhaus-westcode-network"],
        "working_dir": "/opt/brockhaus",
        "compose_service": "brockhaus",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/brockhaus",
        "is_ecr": True,
    },
    {
        "slug": "hilde-web",
        "repo": "westcoder/hilde-web",
        "local_dir": "hilde-web",
        "hosts": ["hsh-westcode-network"],
        "working_dir": "/opt/hilde-web",
        "compose_service": "hilde-web",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/hilde-web",
        "is_ecr": True,
    },
    {
        "slug": "linklama",
        "repo": "westcoder/linklama",
        "local_dir": "linklama",
        "hosts": ["linkla-ma"],
        "working_dir": "/opt/linklama",
        "compose_service": "linklama",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/linklama",
        "is_ecr": True,
    },
    {
        "slug": "ses-service-app",
        "repo": "westcoder/ses-service-app",
        "local_dir": "ses-service-app",
        "hosts": ["service-ses-sandmann-de"],
        "working_dir": "/opt/ses-service-app",
        "compose_service": "ses-service-app",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/ses-service-app",
        "is_ecr": True,
    },
    {
        "slug": "ses-sl-sw-sync",
        "repo": "westcoder/ses-sl-sw-sync",
        "local_dir": "ses-sl-sw-sync",
        "hosts": ["service-ses-sandmann-de"],
        "working_dir": "/opt/ses-sl-sw-sync",
        "compose_service": "ses-s4",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/ses-s4",
        "is_ecr": True,
    },
    {
        "slug": "ses-shop",
        "repo": "westcoder/ses-shop",
        "local_dir": "ses-shop",
        "hosts": ["cdn-ses-sandmann-de"],
        "working_dir": "/opt/ses-shop",
        "compose_service": "ses-shop",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/ses-shop",
        "is_ecr": True,
    },
    {
        "slug": "deenge",
        "repo": "westcoder/deenge",
        "local_dir": "deenge",
        "hosts": ["service-deenge-de"],
        "working_dir": "/opt/deenge",
        "compose_service": "deenge",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/deenge",
        "is_ecr": True,
    },
    {
        "slug": "wuerth-converter",
        "repo": "westcoder/wuerth-converter",
        "local_dir": "wuerth-converter",
        "hosts": ["converter-westcode-de"],
        "working_dir": "/opt/wuerth-converter",
        "compose_service": "wuerth-converter",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/wuerth_converter",
        "is_ecr": True,
    },
    {
        "slug": "csa",
        "repo": "westcoder/csa",
        "local_dir": "csa",
        "hosts": ["c2-westcode-network"],
        "working_dir": "/opt/csa",
        "compose_service": "csa",
        "image_repo": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/csa",
        "is_ecr": True,
    },
    {
        "slug": "coder",
        "repo": "westcoder/coder-hosting",
        "local_dir": "coder-hosting",
        "hosts": ["remote-westcode-de", "dev-westcode-de"],
        "working_dir": "/opt/coder",
        "compose_service": "coder",
        "image_repo": "ghcr.io/coder/coder",
        "is_ecr": False,
    },
]

_VERSION_RE = re.compile(r'version\s*=\s*"([^"]+)"')
_BUMP_TITLE_RE = re.compile(
    r"(?:bump|update)\s+([^\s]+)\s+from\s+v?([^\s]+)\s+to\s+v?([^\s]+)(?:\s+in\s+([^\s]+))?",
    re.IGNORECASE,
)


def _detect_local_repo_version(repo_dir: Path) -> str:
    if not repo_dir.exists():
        return "main"
    for candidate in (
        repo_dir / "pyproject.toml",
        repo_dir / "backend" / "pyproject.toml",
    ):
        if candidate.exists():
            m = _VERSION_RE.search(candidate.read_text(errors="ignore"))
            if m:
                return m.group(1)
    for candidate in (
        repo_dir / "package.json",
        repo_dir / "frontend" / "package.json",
        repo_dir / "service" / "package.json",
    ):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text(errors="ignore"))
                ver = str(data.get("version") or "").strip()
                if ver and ver != "0.0.0":
                    return ver
            except Exception:
                pass
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return "main"


def _is_local_git_clean(repo_dir: Path) -> bool:
    if not repo_dir.exists():
        return True
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return proc.returncode == 0 and proc.stdout.strip() == ""
    except Exception:
        return True


def fetch_github_open_prs(owner: str = "westcoder") -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(
            [
                "gh",
                "search",
                "prs",
                "--owner",
                owner,
                "--state",
                "open",
                "--json",
                "repository,number,title,url,updatedAt",
                "--limit",
                "100",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        raw_prs = json.loads(proc.stdout)
    except Exception:
        return []

    parsed_prs: list[dict[str, Any]] = []
    for item in raw_prs:
        repo_info = item.get("repository") or {}
        repo_full = str(repo_info.get("nameWithOwner") or "")
        repo_name = str(repo_info.get("name") or "")
        if not repo_name:
            continue
        title = str(item.get("title") or "").strip()
        pr_number = item.get("number")
        pr_url = str(item.get("url") or "")

        service_slug = "coder" if repo_name == "coder-hosting" else repo_name
        m = _BUMP_TITLE_RE.search(title)
        if m:
            dep_name, cur_ver, target_ver, subdir = (
                m.group(1),
                m.group(2),
                m.group(3),
                m.group(4) or "",
            )
            file_path = f"{subdir.lstrip('/')}/lockfile ({dep_name})" if subdir else f"deps ({dep_name})"
            parsed_prs.append(
                {
                    "service_slug": service_slug,
                    "repo_full_name": repo_full,
                    "file_path": file_path,
                    "pr_number": pr_number,
                    "pr_url": pr_url,
                    "ci_status": "success",
                    "dependency_name": dep_name,
                    "current_version": cur_ver,
                    "target_version": f"{dep_name} {target_ver}",
                }
            )
            continue

        parsed = parse_renovate_pr(
            {
                "number": pr_number,
                "title": title,
                "html_url": pr_url,
            },
            repo_full_name=repo_full,
            file_path=title[:90],
            ci_status="success",
        )
        if parsed:
            parsed["service_slug"] = service_slug
            parsed_prs.append(parsed)
        elif any(kw in title.lower() for kw in ("bump", "update", "deps", "upgrade", "fix", "feat")):
            parsed_prs.append(
                {
                    "service_slug": service_slug,
                    "repo_full_name": repo_full,
                    "file_path": title[:90],
                    "pr_number": pr_number,
                    "pr_url": pr_url,
                    "ci_status": "success",
                    "dependency_name": repo_name,
                    "current_version": "",
                    "target_version": f"PR #{pr_number}",
                }
            )
    return parsed_prs


def scan_local_repo_with_trivy(repo_dir: Path) -> list[dict[str, Any]]:
    if not repo_dir.exists():
        return []
    try:
        proc = subprocess.run(
            [
                "trivy",
                "fs",
                "--scanners",
                "vuln",
                "--severity",
                "MEDIUM,HIGH,CRITICAL",
                "--skip-dirs",
                "node_modules,.venv,.claude,.git,dist",
                "--quiet",
                "--format",
                "json",
                str(repo_dir),
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        report = json.loads(proc.stdout)
    except Exception:
        return []

    seen: set[tuple[str, str]] = set()
    vulns: list[dict[str, Any]] = []
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vid = str(v.get("VulnerabilityID") or "").strip()
            pkg = str(v.get("PkgName") or "").strip()
            fixed = str(v.get("FixedVersion") or "").strip()
            if not vid or not fixed:
                continue
            key = (vid, pkg)
            if key in seen:
                continue
            seen.add(key)
            installed = str(v.get("InstalledVersion") or "").strip()
            raw_title = str(v.get("Title") or v.get("Description") or "").strip()
            vulns.append(
                {
                    "VulnerabilityID": vid,
                    "Severity": str(v.get("Severity") or "HIGH").upper(),
                    "Status": str(v.get("Status") or "fixed"),
                    "FixedVersion": f"{pkg} {fixed}" if pkg else fixed,
                    "PkgName": f"{pkg} ({installed})" if installed else pkg,
                    "Title": raw_title or f"{pkg}: Update auf {fixed}",
                }
            )
    return vulns


def run_live_sync(
    projects_root: Path = Path("/Users/pietzschke/projects"),
    run_trivy: bool = True,
    run_gh: bool = True,
) -> dict[str, Any]:
    infra_root = projects_root / "westcode-infra"
    if infra_root.exists():
        # Clean up any non-infra stray hosts if present
        sync_infra_hosts(infra_root)

    # v2: containers are only ever created from real agent reports (no synthetic records).

    if run_gh:
        prs = fetch_github_open_prs("westcoder")
    else:
        from catalog.models import GitTarget

        prs = [
            {
                "service_slug": gt.service_group.slug,
                "repo_full_name": gt.repo_full_name,
                "file_path": gt.file_path,
                "pr_number": gt.pr_number,
                "pr_url": gt.pr_url,
                "ci_status": gt.ci_status,
                "target_version": gt.target_version,
            }
            for gt in GitTarget.objects.select_related("service_group").all()
        ]

    trivy_findings: dict[str, list[dict[str, Any]]] = {}
    total_vulns = 0
    if run_trivy:
        for spec in WESTCODE_SERVICE_DEPLOYMENTS:
            slug = spec["slug"]
            repo_dir = projects_root / spec["local_dir"]
            vulns = scan_local_repo_with_trivy(repo_dir)
            if vulns:
                trivy_findings[slug] = vulns
                total_vulns += len(vulns)
    else:
        from catalog.models import VulnerabilityFinding

        for vf in VulnerabilityFinding.objects.select_related("service_group").all():
            slug = vf.service_group.slug
            trivy_findings.setdefault(slug, []).append(
                {
                    "VulnerabilityID": vf.vulnerability_id,
                    "Severity": vf.severity,
                    "Status": vf.status,
                    "FixedVersion": vf.fixed_version,
                    "PkgName": vf.package_name,
                    "Title": vf.title,
                }
            )
            total_vulns += 1

    groups = rebuild_service_groups(
        renovate_prs=prs,
        trivy_findings=trivy_findings,
        upstream_releases={},
    )

    return {
        "status": "ok",
        "hosts_count": Host.objects.count(),
        "services_count": len(groups),
        "prs_count": len(prs),
        "vulns_count": total_vulns,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }
