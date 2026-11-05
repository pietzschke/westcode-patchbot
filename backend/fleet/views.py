"""Read-only host views for the dashboard plus the admin-only agent token generator."""

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

from fleet.models import Host
from inventory.permissions import IsTeamAdmin


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
