import re
from collections import defaultdict
from typing import Any
from django.db import transaction

from catalog.models import GitTarget, HostTarget, ServiceGroup, VulnerabilityFinding
from catalog.trivy import SEVERITY_RANK, filter_actionable_vulns
from fleet.models import Host, HostContainer

KNOWN_IMAGE_ALIASES: dict[str, str] = {
    "plausible/analytics": "plausible",
    "plausible/community-edition": "plausible",
    "plausible": "plausible",
    "maptiler/tileserver-gl-light": "tileserver",
    "maptiler/tileserver-gl": "tileserver",
    "tileserver-gl-light": "tileserver",
    "tileserver": "tileserver",
    "valhalla/valhalla": "valhalla",
    "valhalla": "valhalla",
    "coder/coder": "coder",
    "coder": "coder",
    "library/postgres": "postgres",
    "postgres": "postgres",
    "postgresql": "postgres",
    "library/traefik": "traefik",
    "traefik": "traefik",
    "django": "django",
}

SERVICE_METADATA: dict[str, tuple[str, str]] = {
    "plausible": ("Plausible Analytics", "plausible"),
    "westcode-hub": ("Westcode Hub", "westcode"),
    "service-center": ("Westcode Service-Center", "westcode"),
    "ack-desk": ("Ackermann Desk", "django"),
    "wyze-agent": ("Wyze Agent", "coder"),
    "projectory": ("Projectory", "westcode"),
    "materialdatenbank": ("Materialdatenbank", "postgres"),
    "masteroil": ("Masteroil Shop & CMS", "django"),
    "brockhaus": ("Brockhaus", "django"),
    "hilde-web": ("Hildegardis-Schule Web", "django"),
    "linklama": ("Linklama Redirects", "traefik"),
    "ses-service-app": ("SES Service-App", "django"),
    "ses-sl-sw-sync": ("SES SelectLine Sync", "postgres"),
    "deenge": ("Deenge Portal", "django"),
    "wuerth-converter": ("Würth Converter", "valhalla"),
    "csa": ("CSA Portal", "westcode"),
    "angular-django-scaffold": ("Angular-Django Scaffold", "westcode"),
    "postgres": ("PostgreSQL", "postgres"),
    "coder": ("Coder", "coder"),
    "traefik": ("Traefik", "traefik"),
    "valhalla": ("Valhalla", "valhalla"),
    "tileserver": ("TileServer GL", "tileserver"),
    "django": ("Django", "django"),
    "ubuntu-apt": ("Ubuntu / Debian apt", "ubuntu"),
    "ubuntu-eol": ("Ubuntu EOL-Upgrade", "ubuntu"),
}

_GENERIC_REPO_SUFFIXES = frozenset({
    "analytics",
    "community-edition",
    "server",
    "backend",
    "frontend",
    "app",
    "ce",
    "ee",
})


def _normalize_repo_to_slug(repo_path: str) -> str:
    cleaned = repo_path.strip().lower()
    if "@" in cleaned:
        cleaned = cleaned.split("@", 1)[0]
    last_slash = cleaned.rfind("/")
    if ":" in cleaned[last_slash + 1 :]:
        cleaned = cleaned[: last_slash + 1] + cleaned[last_slash + 1 :].split(":", 1)[0]

    if cleaned in KNOWN_IMAGE_ALIASES:
        return KNOWN_IMAGE_ALIASES[cleaned]

    parts = [p for p in cleaned.split("/") if p]
    if not parts:
        return "unknown"

    # Strip registry domain if first segment looks like a hostname (contains '.' or ':' or 'localhost')
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]

    joined = "/".join(parts)
    if joined in KNOWN_IMAGE_ALIASES:
        return KNOWN_IMAGE_ALIASES[joined]

    if len(parts) >= 2 and parts[-1] in _GENERIC_REPO_SUFFIXES:
        candidate = parts[-2]
    else:
        candidate = parts[-1]

    return KNOWN_IMAGE_ALIASES.get(candidate, candidate)


def _display_name_and_logo(slug: str) -> tuple[str, str]:
    if slug in SERVICE_METADATA:
        return SERVICE_METADATA[slug]
    display_name = slug.replace("-", " ").replace("_", " ").title()
    return (display_name, slug)


def _extract_tag_from_image_ref(image_tag: str) -> str:
    last_slash = image_tag.rfind("/")
    tail = image_tag[last_slash + 1 :]
    if ":" in tail:
        raw_tag = tail.split(":", 1)[1].strip()
        return re.sub(r"^v(?=\d)", "", raw_tag)
    return ""


def resolve_container_identity(container: HostContainer) -> tuple[str, str, str]:
    """Resolve (service_slug, display_name, running_version) using repo_digests and OCI labels."""
    if container.oci_title and container.oci_title.strip():
        slug = _normalize_repo_to_slug(container.oci_title)
    elif container.repo_digests:
        slug = _normalize_repo_to_slug(str(container.repo_digests[0]))
    else:
        slug = _normalize_repo_to_slug(container.image_tag)

    display_name, _ = _display_name_and_logo(slug)

    if container.oci_revision and container.oci_revision.strip():
        running_version = container.oci_revision.strip()
    else:
        tag_version = _extract_tag_from_image_ref(container.image_tag)
        if tag_version:
            running_version = tag_version
        elif container.repo_digests:
            first_digest = str(container.repo_digests[0])
            running_version = first_digest.split("@", 1)[1] if "@" in first_digest else container.image_id
        else:
            running_version = container.image_id or "unknown"

    return (slug, display_name, running_version)


def _parse_finding_key(raw_key: str) -> tuple[str, str | None]:
    """Parse a trivy_findings key into (service_slug, optional_tag_or_digest)."""
    key = raw_key.strip()
    if "@" in key:
        repo_part, digest_part = key.split("@", 1)
        return (_normalize_repo_to_slug(repo_part), digest_part.strip())

    last_slash = key.rfind("/")
    tail = key[last_slash + 1 :]
    if ":" in tail:
        repo_part = key[: last_slash + 1] + tail.split(":", 1)[0]
        tag_part = tail.split(":", 1)[1].strip()
        return (_normalize_repo_to_slug(repo_part), re.sub(r"^v(?=\d)", "", tag_part))

    return (_normalize_repo_to_slug(key), None)


def _is_ecr_container(container: HostContainer) -> bool:
    if ".dkr.ecr." in (container.image_tag or ""):
        return True
    for digest in container.repo_digests or []:
        if ".dkr.ecr." in str(digest):
            return True
    return False


def rebuild_service_groups(
    renovate_prs: list[dict[str, Any]] | None = None,
    trivy_findings: dict[str, list[dict[str, Any]]] | None = None,
    upstream_releases: dict[str, str] | None = None,
) -> list[ServiceGroup]:
    """Correlate running containers, Renovate PRs, Trivy CVEs, and host apt/EOL state into ServiceGroups."""
    renovate_prs = renovate_prs or []
    trivy_findings = trivy_findings or {}
    upstream_releases = upstream_releases or {}

    with transaction.atomic():
        ServiceGroup.objects.all().delete()

        # 1. Index running containers by resolved service_slug
        containers_by_slug: dict[str, list[ tuple[HostContainer, str, str] ]] = defaultdict(list)
        active_refs_by_slug: dict[str, set[str]] = defaultdict( lambda: {"main", "develop"} )

        for container in HostContainer.objects.select_related("host").all():
            if container.status and container.status != "running":
                continue
            slug, display_name, running_version = resolve_container_identity(container)
            containers_by_slug[slug].append((container, display_name, running_version))
            if running_version:
                active_refs_by_slug[slug].add(running_version)
                active_refs_by_slug[slug].add(f"v{running_version}")
            if container.oci_revision:
                active_refs_by_slug[slug].add(container.oci_revision.strip())
            if container.image_id:
                active_refs_by_slug[slug].add(container.image_id.strip())
            for digest in container.repo_digests or []:
                digest_str = str(digest).strip()
                active_refs_by_slug[slug].add(digest_str)
                if "@" in digest_str:
                    active_refs_by_slug[slug].add(digest_str.split("@", 1)[1])

        # 2. Index open Renovate PRs by service_slug
        prs_by_slug: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for pr in renovate_prs:
            raw_slug = str(pr.get("service_slug") or "").strip()
            if not raw_slug:
                continue
            slug = _normalize_repo_to_slug(raw_slug)
            prs_by_slug[slug].append(pr)
            target_ver = str(pr.get("target_version") or "").strip()
            if target_ver:
                active_refs_by_slug[slug].add(target_ver)
                active_refs_by_slug[slug].add(re.sub(r"^v(?=\d)", "", target_ver))

        # Active services must either run on at least one VM or have an open Renovate PR
        active_slugs: set[str] = set(containers_by_slug.keys()) | set(prs_by_slug.keys())

        # 3. Filter and bucket Trivy findings for active services and active tags/digests only
        vulns_by_slug: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for raw_key, raw_vuln_list in trivy_findings.items():
            slug, tag_or_digest = _parse_finding_key(raw_key)
            if slug not in active_slugs:
                # Dead ECR repository / inactive service not running on any VM and with no open PR
                continue
            if tag_or_digest is not None and tag_or_digest not in active_refs_by_slug[slug]:
                # Historical ECR tag (e.g. keep_10 history) not running on any VM and not main/develop
                continue
            actionable = filter_actionable_vulns(raw_vuln_list)
            if actionable:
                vulns_by_slug[slug].extend(actionable)

        created_groups: list[ServiceGroup] = []

        # 4. Build ServiceGroups for active container/git services that have actionable work
        for slug in sorted(active_slugs):
            container_entries = containers_by_slug.get(slug, [])
            pr_entries = prs_by_slug.get(slug, [])
            vuln_entries = vulns_by_slug.get(slug, [])
            upstream_target = str(upstream_releases.get(slug) or "").strip()

            running_versions = sorted({ver for _, _, ver in container_entries if ver})
            current_version_summary = " – ".join(running_versions) if running_versions else ""

            target_version = upstream_target
            if not target_version and pr_entries:
                target_version = str(pr_entries[0].get("target_version") or "").strip()
            if not target_version and vuln_entries:
                target_version = str(vuln_entries[0].get("FixedVersion") or "").strip()

            has_version_update = bool(
                target_version
                and (not running_versions or any(v != target_version for v in running_versions))
            )

            # Skip idle running services that have no actionable CVEs, no open PRs, and no pending version update
            if not vuln_entries and not pr_entries and not has_version_update:
                continue

            display_name, logo_key = _display_name_and_logo(slug)
            if container_entries and slug not in SERVICE_METADATA:
                display_name = container_entries[0][1]

            highest_cve_id = ""
            highest_severity = ""
            summary_line = ""

            if vuln_entries:
                sorted_vulns = sorted(
                    vuln_entries,
                    key=lambda v: SEVERITY_RANK.get(str(v.get("Severity") or "").upper(), 0),
                    reverse=True,
                )
                best_vuln = sorted_vulns[0]
                highest_cve_id = str(best_vuln.get("VulnerabilityID") or "")
                highest_severity = str(best_vuln.get("Severity") or "").upper()
                best_title = str(
                    best_vuln.get("Title")
                    or best_vuln.get("Description")
                    or f"Sicherheitsupdate auf {target_version}"
                )
                if len(sorted_vulns) > 1:
                    summary_line = f"{len(sorted_vulns)} behebbare CVEs · {best_title}"
                else:
                    summary_line = best_title
                category = "action_required"
            else:
                sorted_vulns = []
                category = "ready_to_rollout"
                if pr_entries:
                    summary_line = f"{len(pr_entries)} offene Update-PRs bereit zum Ausrollen"
                elif target_version:
                    summary_line = f"Neue Version {target_version} bereit zum Ausrollen"
                else:
                    summary_line = "Update bereit zum Ausrollen"

            sg = ServiceGroup.objects.create(
                slug=slug,
                display_name=display_name,
                logo_key=logo_key,
                category=category,
                current_version_summary=current_version_summary,
                target_version=target_version,
                highest_cve_id=highest_cve_id,
                highest_severity=highest_severity,
                summary_line=summary_line[:250],
            )

            for vuln in sorted_vulns[:25]:
                VulnerabilityFinding.objects.create(
                    service_group=sg,
                    vulnerability_id=str(vuln.get("VulnerabilityID") or "")[:120],
                    severity=str(vuln.get("Severity") or "").upper()[:32],
                    status=str(vuln.get("Status") or "fixed")[:32],
                    fixed_version=str(vuln.get("FixedVersion") or "")[:120],
                    title=str(vuln.get("Title") or "")[:250],
                    package_name=str(vuln.get("PkgName") or "")[:120],
                )

            for pr in pr_entries:
                GitTarget.objects.create(
                    service_group=sg,
                    repo_full_name=str(pr.get("repo_full_name") or ""),
                    file_path=str(pr.get("file_path") or ""),
                    pr_number=pr.get("pr_number"),
                    pr_url=str(pr.get("pr_url") or ""),
                    ci_status=str(pr.get("ci_status") or ""),
                    target_version=str(pr.get("target_version") or target_version),
                )

            for container, _, running_ver in container_entries:
                target_type = "ecr_app" if _is_ecr_container(container) else "compose"
                HostTarget.objects.create(
                    service_group=sg,
                    host=container.host,
                    target_type=target_type,
                    working_dir=container.working_dir or "",
                    compose_service=container.compose_service or "",
                    running_version=running_ver,
                    target_version=target_version or running_ver,
                    git_clean=container.git_clean,
                )

            created_groups.append(sg)

        # 5. Automatically generate 'ubuntu-apt' service group from Host / HostPackage
        hosts_with_pkgs = [
            h for h in Host.objects.prefetch_related("packages").all() if h.packages.all()
        ]
        if hosts_with_pkgs:
            total_pkgs = sum(len(h.packages.all()) for h in hosts_with_pkgs)
            sec_pkgs = sum(
                1 for h in hosts_with_pkgs for p in h.packages.all() if p.is_security_update
            )
            has_security = sec_pkgs > 0
            apt_category = "action_required" if has_security else "ready_to_rollout"
            apt_severity = "HIGH" if has_security else ""
            apt_summary = (
                f"{sec_pkgs} Sicherheits-Updates ({total_pkgs} Pakete gesamt) auf {len(hosts_with_pkgs)} Hosts"
                if has_security
                else f"{total_pkgs} Systempaket-Updates auf {len(hosts_with_pkgs)} Hosts bereit"
            )
            apt_group = ServiceGroup.objects.create(
                slug="ubuntu-apt",
                display_name="Ubuntu / Debian apt",
                logo_key="ubuntu",
                category=apt_category,
                current_version_summary=f"{len(hosts_with_pkgs)} Hosts",
                target_version="dist-upgrade",
                highest_cve_id="",
                highest_severity=apt_severity,
                summary_line=apt_summary,
            )
            for host in hosts_with_pkgs:
                pkg_count = len(host.packages.all())
                HostTarget.objects.create(
                    service_group=apt_group,
                    host=host,
                    target_type="apt",
                    working_dir="",
                    compose_service="",
                    running_version=f"{host.os_distro} {host.os_version}".strip() or (host.declared_image or ""),
                    target_version=f"{pkg_count} Pakete",
                    git_clean=None,
                )
            created_groups.append(apt_group)

        # 6. Automatically generate 'ubuntu-eol' service group from EOL Hosts
        eol_hosts = list(Host.objects.filter(is_os_eol=True))
        if eol_hosts:
            eol_versions = sorted(
                {h.os_version or h.declared_image or "20.04" for h in eol_hosts}
            )
            eol_group = ServiceGroup.objects.create(
                slug="ubuntu-eol",
                display_name="Ubuntu EOL-Upgrade",
                logo_key="ubuntu",
                category="action_required",
                current_version_summary=" / ".join(eol_versions),
                target_version="24.04 LTS",
                highest_cve_id="OS-EOL",
                highest_severity="HIGH",
                summary_line=f"{len(eol_hosts)} Server auf abgelaufenem Betriebssystem-Release (EOL)",
            )
            for host in eol_hosts:
                HostTarget.objects.create(
                    service_group=eol_group,
                    host=host,
                    target_type="os_eol",
                    working_dir="",
                    compose_service="",
                    running_version=host.os_version or host.declared_image or "20.04",
                    target_version="24.04 LTS",
                    git_clean=None,
                )
            created_groups.append(eol_group)

        return created_groups
