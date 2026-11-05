import hashlib
import secrets
import shlex
from typing import Any

from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from catalog.correlator import PROJECT_STACK_METADATA
from catalog.live_sync import run_live_sync
from catalog.models import ServiceGroup
from fleet.models import Host
from inventory.permissions import IsTeamAdmin


def _project_display_name_and_logo(stack_name: str) -> tuple[str, str]:
    if stack_name in PROJECT_STACK_METADATA:
        return PROJECT_STACK_METADATA[stack_name]
    cleaned = stack_name.removeprefix("hetzner-").replace("-", " ").title()
    return (cleaned or "Infrastruktur", "westcode")


def serialize_service_group(sg: ServiceGroup) -> dict[str, Any]:
    host_targets_qs = list(sg.host_targets.select_related("host").all())
    seen_stacks: set[str] = set()
    projects: list[dict[str, str]] = []
    for ht in host_targets_qs:
        st = ht.host.stack_name
        if st and st not in seen_stacks:
            seen_stacks.add(st)
            p_name, p_logo = _project_display_name_and_logo(st)
            projects.append({"slug": st, "display_name": p_name, "logo_key": p_logo})

    return {
        "id": sg.id,
        "slug": sg.slug,
        "display_name": sg.display_name,
        "logo_key": sg.logo_key,
        "category": sg.category,
        "current_version_summary": sg.current_version_summary,
        "target_version": sg.target_version,
        "highest_cve_id": sg.highest_cve_id,
        "highest_severity": sg.highest_severity,
        "summary_line": sg.summary_line,
        "projects": projects,
        "git_targets": [
            {
                "id": gt.id,
                "repo_full_name": gt.repo_full_name,
                "file_path": gt.file_path,
                "pr_number": gt.pr_number,
                "pr_url": gt.pr_url,
                "ci_status": gt.ci_status,
                "target_version": gt.target_version,
            }
            for gt in sg.git_targets.all()
        ],
        "host_targets": [
            {
                "id": ht.id,
                "host_slug": ht.host.slug,
                "hostname": ht.host.hostname,
                "stack_name": ht.host.stack_name,
                "project_name": _project_display_name_and_logo(ht.host.stack_name)[0],
                "target_type": ht.target_type,
                "working_dir": ht.working_dir,
                "compose_service": ht.compose_service,
                "running_version": ht.running_version,
                "target_version": ht.target_version,
                "git_clean": ht.git_clean,
            }
            for ht in host_targets_qs
        ],
        "vulnerabilities": [
            {
                "id": v.id,
                "vulnerability_id": v.vulnerability_id,
                "severity": v.severity,
                "status": v.status,
                "fixed_version": v.fixed_version,
                "title": v.title,
                "package_name": v.package_name,
            }
            for v in sg.vulnerabilities.all()
        ],
    }


def _iso(value: Any) -> str | None:
    return value.isoformat() if value else None


def serialize_host(host: Host) -> dict[str, Any]:
    # The agent reports every installed package; only rows with an upgrade
    # candidate are pending apt updates. Installed-only rows feed verification.
    all_pkgs = list(host.packages.all())
    pending = [p for p in all_pkgs if p.candidate_version]
    containers = list(host.containers.all())
    sec_count = sum(1 for p in pending if p.is_security_update)
    distro_str = f"{host.os_distro} {host.os_version}".strip() or (host.declared_image or "unbekannt")
    project = host.project
    return {
        "id": host.id,
        "slug": host.slug,
        "hostname": host.hostname,
        "provider": host.provider,
        "stack": host.stack_name,
        "stack_name": host.stack_name,
        "declared_image": host.declared_image,
        "distro": distro_str,
        "os_distro": host.os_distro,
        "os_version": host.os_version,
        "os_eol_date": _iso(host.os_eol_date),
        "is_eol": host.is_os_eol,
        "is_os_eol": host.is_os_eol,
        "kernel_version": host.kernel_version,
        "reboot_required": host.reboot_required,
        "agent_version": host.agent_version,
        "apt_lists_updated_at": _iso(host.apt_lists_updated_at),
        "last_seen_at": _iso(host.last_seen_at),
        "has_agent_token": bool(host.agent_token_hash),
        "project": {"slug": project.slug, "name": project.name} if project else None,
        "installed_package_count": len(all_pkgs),
        "pending_apt_count": len(pending),
        "security_apt_count": sec_count,
        "actionable_packages_count": len(pending),
        "container_count": len(containers),
        "containers_count": len(containers),
        "containers": [
            {
                "name": c.name,
                "image_tag": c.image_tag,
                "repo_digests": list(c.repo_digests or []),
                "oci_title": c.oci_title,
                "oci_revision": c.oci_revision,
                "oci_source": c.oci_source,
                "image_created_at": _iso(c.image_created_at),
                "working_dir": c.working_dir,
                "compose_service": c.compose_service,
                "git_head_sha": c.git_head_sha,
                "git_clean": c.git_clean,
                "status": c.status,
            }
            for c in containers
        ],
        "packages": [
            {
                "name": p.name,
                "installed_version": p.installed_version,
                "candidate_version": p.candidate_version,
                "is_security_update": p.is_security_update,
                "source_pocket": p.source_pocket,
            }
            for p in pending
        ],
    }


class ServiceListView(APIView):

    def get(self, request: Request) -> Response:
        groups = ServiceGroup.objects.prefetch_related(
            "git_targets",
            "host_targets__host",
            "vulnerabilities",
        ).all()
        return Response(
            [serialize_service_group(sg) for sg in groups],
            status=status.HTTP_200_OK,
        )


class HostListView(APIView):

    def get(self, request: Request) -> Response:
        hosts = Host.objects.select_related("project").prefetch_related("packages", "containers").all()
        return Response(
            [serialize_host(h) for h in hosts],
            status=status.HTTP_200_OK,
        )


class HostDetailView(APIView):

    def get(self, request: Request, slug: str) -> Response:
        host = get_object_or_404(
            Host.objects.select_related("project").prefetch_related("packages", "containers"), slug=slug
        )
        return Response(serialize_host(host), status=status.HTTP_200_OK)


class HostTokenGenerateView(APIView):
    permission_classes = [IsTeamAdmin]

    def post(self, request: Request, slug: str) -> Response:
        host = get_object_or_404(Host, slug=slug)
        raw_token = secrets.token_urlsafe(32)
        host.agent_token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        host.save(update_fields=["agent_token_hash"])
        # deploy/install-agent.sh reads its configuration from environment variables.
        base_url = settings.PATCHBOT_BASE_URL or request.build_absolute_uri("/").rstrip("/")
        install_cmd = (
            f"sudo PATCHBOT_URL={shlex.quote(base_url)} PATCHBOT_TOKEN={shlex.quote(raw_token)} "
            f"PATCHBOT_HOSTNAME={shlex.quote(host.hostname)} ./deploy/install-agent.sh"
        )
        return Response(
            {
                "slug": host.slug,
                "hostname": host.hostname,
                "token": raw_token,
                "install_command": install_cmd,
                "host": serialize_host(host),
            },
            status=status.HTTP_200_OK,
        )


class ProjectListView(APIView):

    def get(self, request: Request) -> Response:
        hosts = list(Host.objects.select_related("project").prefetch_related("packages", "containers").all())
        groups = list(
            ServiceGroup.objects.exclude(slug__in=["ubuntu-apt", "ubuntu-eol"])
            .prefetch_related("git_targets", "host_targets__host", "vulnerabilities")
            .all()
        )

        hosts_by_stack: dict[str, list[Host]] = {}
        for h in hosts:
            hosts_by_stack.setdefault(h.stack_name or "default", []).append(h)

        services_by_stack: dict[str, list[ServiceGroup]] = {}
        for sg in groups:
            stack_names = {
                ht.host.stack_name
                for ht in sg.host_targets.all()
                if ht.host and ht.host.stack_name
            }
            for st in stack_names:
                services_by_stack.setdefault(st, []).append(sg)

        all_stacks = sorted(set(hosts_by_stack.keys()) | set(services_by_stack.keys()))
        result: list[dict[str, Any]] = []

        for stack_name in all_stacks:
            stack_hosts = hosts_by_stack.get(stack_name, [])
            stack_services = services_by_stack.get(stack_name, [])
            display_name, logo_key = _project_display_name_and_logo(stack_name)

            serialized_hosts = [serialize_host(h) for h in stack_hosts]
            serialized_services = [serialize_service_group(sg) for sg in stack_services]

            cves_count = sum(len(s["vulnerabilities"]) for s in serialized_services)
            prs_count = sum(len(s["git_targets"]) for s in serialized_services)
            pending_apt_count = sum(h["pending_apt_count"] for h in serialized_hosts)
            security_apt_count = sum(h["security_apt_count"] for h in serialized_hosts)
            has_eol_host = any(h["is_os_eol"] for h in serialized_hosts)
            has_reboot_required = any(h["reboot_required"] for h in serialized_hosts)
            has_git_dirty = any(
                ht["git_clean"] is False
                for s in serialized_services
                for ht in s["host_targets"]
                if ht.get("stack_name") == stack_name
            )

            is_urgent = (
                cves_count > 0
                or has_eol_host
                or security_apt_count > 0
                or any(s["category"] == "action_required" for s in serialized_services)
            )
            category = "action_required" if is_urgent else "ready_to_rollout"

            host_names = ", ".join(h["hostname"] for h in serialized_hosts)
            svc_names = ", ".join(s["display_name"] for s in serialized_services)
            summary_parts = []
            if svc_names:
                summary_parts.append(f"Dienste: {svc_names}")
            if host_names:
                summary_parts.append(f"Hosts: {host_names}")
            summary_line = " · ".join(summary_parts)

            result.append(
                {
                    "slug": stack_name,
                    "display_name": display_name,
                    "logo_key": logo_key,
                    "category": category,
                    "summary_line": summary_line,
                    "cves_count": cves_count,
                    "prs_count": prs_count,
                    "pending_apt_count": pending_apt_count,
                    "security_apt_count": security_apt_count,
                    "has_eol_host": has_eol_host,
                    "has_reboot_required": has_reboot_required,
                    "has_git_dirty": has_git_dirty,
                    "hosts": serialized_hosts,
                    "services": serialized_services,
                }
            )

        result.sort(
            key=lambda p: (
                0 if p["category"] == "action_required" else 1,
                -len(p["services"]),
                -p["cves_count"],
                p["display_name"],
            )
        )
        return Response(result, status=status.HTTP_200_OK)


class LiveSyncView(APIView):

    def post(self, request: Request) -> Response:
        summary = run_live_sync()
        return Response(summary, status=status.HTTP_200_OK)
