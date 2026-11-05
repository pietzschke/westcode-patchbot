from datetime import date
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from fleet.auth import HostTokenAuthentication
from fleet.infra_sync import distro_eol_date, is_distro_eol
from fleet.models import Host, HostContainer, HostPackage
from inventory.matching import link_containers_to_repositories

def _parse_timestamp(value: object):
    """Parse an ISO 8601 timestamp from the agent; invalid or missing values become None."""
    if not value:
        return None
    try:
        return parse_datetime(str(value))
    except ValueError:
        return None


def _get_authenticated_host(request: Request) -> Host | None:
    if isinstance(request.auth, Host):
        return request.auth
    return None


def _container_fields(c: dict, now) -> dict:
    """Telemetry fields of one reported container (everything except the curated links)."""
    return {
        "container_id": str(c["container_id"]),
        "name": str(c["name"]),
        "image_tag": str(c.get("image_tag", "")),
        "image_id": str(c.get("image_id", "")),
        "repo_digests": list(c.get("repo_digests") or []),
        "oci_title": str(c.get("oci_title", "")),
        "oci_revision": str(c.get("oci_revision", "")),
        "oci_source": str(c.get("oci_source", "") or "")[:512],
        "image_created_at": _parse_timestamp(c.get("image_created_at")),
        "git_head_sha": str(c.get("git_head_sha", "") or "")[:64],
        "reported_at": now,
        "working_dir": str(c.get("working_dir", "")),
        "compose_service": str(c.get("compose_service", "")),
        "git_clean": c.get("git_clean", None),
        "status": str(c.get("status", "running")),
    }


def _sync_containers(host: Host, containers_data: list, now) -> None:
    """Update the host's containers in place so curated links survive each report.

    Containers are re-created by Docker on every deploy (new id), so the stable identity is
    ``(name, compose_service)`` with a fallback to ``name`` alone. Matched rows keep their
    ``project``/``suggested_project``/``repository`` links; rows no longer reported are deleted;
    new rows and rows whose OCI source changed are linked to their repository right away.
    """
    existing = list(host.containers.all())
    by_key = {(c.name, c.compose_service): c for c in existing}
    by_name: dict[str, HostContainer] = {}
    for c in existing:
        by_name.setdefault(c.name, c)

    kept_ids: set[int] = set()
    to_link: list[int] = []
    for raw in containers_data:
        fields = _container_fields(raw, now)
        row = by_key.get((fields["name"], fields["compose_service"]))
        if row is None or row.id in kept_ids:
            row = by_name.get(fields["name"])
        if row is None or row.id in kept_ids:
            row = HostContainer.objects.create(host=host, **fields)
            kept_ids.add(row.id)
            to_link.append(row.id)
            continue
        update_fields = list(fields)
        if row.oci_source != fields["oci_source"] and row.repository_id is not None:
            row.repository = None
            update_fields.append("repository")
        for name, value in fields.items():
            setattr(row, name, value)
        row.save(update_fields=update_fields)
        kept_ids.add(row.id)
        if row.repository_id is None:
            to_link.append(row.id)

    host.containers.exclude(id__in=kept_ids).delete()
    if to_link:
        link_containers_to_repositories(HostContainer.objects.filter(id__in=to_link))


class AgentReportView(APIView):
    authentication_classes = [HostTokenAuthentication]
    permission_classes = []

    def post(self, request: Request) -> Response:
        host = _get_authenticated_host(request)
        if host is None:
            return Response(
                {"detail": "Host authentication required."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        payload = request.data if isinstance(request.data, dict) else {}
        reported_hostname = payload.get("hostname")
        if reported_hostname != host.hostname:
            return Response(
                {"detail": "Payload hostname does not match authenticated host."},
                status=status.HTTP_403_FORBIDDEN,
            )

        os_distro = str(payload.get("os_distro", "") or "").strip()
        os_version = str(payload.get("os_version", "") or "").strip()
        reboot_required = bool(payload.get("reboot_required", False))
        eol = (
            is_distro_eol(os_distro, os_version, today=date.today())
            if (os_distro and os_version)
            else False
        )

        packages_data = payload.get("packages") or []
        containers_data = payload.get("containers") or []

        now = timezone.now()
        with transaction.atomic():
            host.os_distro = os_distro
            host.os_version = os_version
            host.is_os_eol = eol
            host.os_eol_date = distro_eol_date(os_distro, os_version) if (os_distro and os_version) else None
            host.kernel_version = str(payload.get("kernel_version", "") or "")[:128]
            host.agent_version = str(payload.get("agent_version", "") or "")[:32]
            host.apt_lists_updated_at = _parse_timestamp(payload.get("apt_lists_updated_at"))
            host.reboot_required = reboot_required
            host.last_seen_at = now
            host.save(
                update_fields=[
                    "os_distro",
                    "os_version",
                    "is_os_eol",
                    "os_eol_date",
                    "kernel_version",
                    "agent_version",
                    "apt_lists_updated_at",
                    "reboot_required",
                    "last_seen_at",
                ]
            )

            host.packages.all().delete()
            if packages_data:
                HostPackage.objects.bulk_create(
                    [
                        HostPackage(
                            host=host,
                            name=str(pkg["name"]),
                            installed_version=str(pkg.get("installed_version", "")),
                            candidate_version=str(pkg.get("candidate_version", "") or ""),
                            is_security_update=bool(pkg.get("is_security_update", False)),
                            source_pocket=str(pkg.get("source_pocket", "") or "")[:64],
                        )
                        for pkg in packages_data
                    ]
                )

            _sync_containers(host, containers_data, now)

        return Response(
            {
                "status": "ok",
                "hostname": host.hostname,
                "is_os_eol": host.is_os_eol,
            },
            status=status.HTTP_200_OK,
        )

