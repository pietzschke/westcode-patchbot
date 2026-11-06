from datetime import date
import logging

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import serializers, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from fleet.auth import HostTokenAuthentication
from fleet.infra_sync import distro_eol_date, is_distro_eol
from fleet.models import Host, HostContainer, HostPackage
from inventory.matching import link_containers_to_repositories
from triage.jobs import enqueue

logger = logging.getLogger(__name__)


def _text(max_length: int, **kwargs) -> serializers.CharField:
    """Optional string field bounded by the model column (missing -> "")."""
    kwargs.setdefault("required", False)
    kwargs.setdefault("default", "")
    return serializers.CharField(max_length=max_length, allow_blank=True, trim_whitespace=False, **kwargs)


class _PackageSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    installed_version = _text(128)
    candidate_version = _text(128)
    is_security_update = serializers.BooleanField(required=False, default=False)
    source_pocket = _text(64)


class _ContainerSerializer(serializers.Serializer):
    container_id = serializers.CharField(max_length=128)
    name = serializers.CharField(max_length=255)
    image_tag = _text(512)
    image_id = _text(255)
    repo_digests = serializers.ListField(child=serializers.CharField(max_length=1024), required=False, default=list)
    oci_title = _text(255)
    oci_revision = _text(128)
    oci_source = _text(512)
    image_created_at = _text(64, allow_null=True)  # parsed leniently; invalid timestamps are stored as NULL
    working_dir = _text(512)
    compose_service = _text(255)
    git_head_sha = _text(64)
    git_clean = serializers.BooleanField(required=False, allow_null=True, default=None)
    status = _text(64, default="running")


class AgentReportSerializer(serializers.Serializer):
    """Shape of the agent report; types and lengths match the fleet models so bad input is a 400, not a 500."""

    hostname = _text(255, allow_null=True)  # informational only, never used for identity (spec §7.2)
    agent_version = _text(32)
    os_distro = _text(64)
    os_version = _text(64)
    kernel_version = _text(128)
    reboot_required = serializers.BooleanField(required=False, default=False)
    apt_lists_updated_at = _text(64, allow_null=True)
    packages = _PackageSerializer(many=True, required=False, default=list)
    containers = _ContainerSerializer(many=True, required=False, default=list)


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
    """Telemetry fields of one validated container (everything except the curated links)."""
    return {
        "container_id": c["container_id"],
        "name": c["name"],
        "image_tag": c["image_tag"],
        "image_id": c["image_id"],
        "repo_digests": list(c["repo_digests"]),
        "oci_title": c["oci_title"],
        "oci_revision": c["oci_revision"],
        "oci_source": c["oci_source"],
        "image_created_at": _parse_timestamp(c["image_created_at"]),
        "git_head_sha": c["git_head_sha"],
        "reported_at": now,
        "working_dir": c["working_dir"],
        "compose_service": c["compose_service"],
        "git_clean": c["git_clean"],
        "status": c["status"],
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

        if not isinstance(request.data, dict):
            return Response({"detail": "Report must be a JSON object."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = AgentReportSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        payload = serializer.validated_data

        # Spec §7.2: the host comes from the token; the hostname field is informational only. `hostname -f`
        # on a VM may legitimately differ from the westcode-infra name, so a mismatch is logged, not rejected.
        reported_hostname = payload.get("hostname") or ""
        if reported_hostname and reported_hostname != host.hostname:
            logger.warning(
                "Agent report for host %s carries hostname %r; ignored (identity comes from the token).",
                host.hostname, reported_hostname[:255],
            )

        os_distro = payload["os_distro"].strip()
        os_version = payload["os_version"].strip()
        reboot_required = payload["reboot_required"]
        eol = (
            is_distro_eol(os_distro, os_version, today=date.today())
            if (os_distro and os_version)
            else False
        )

        packages_data = payload["packages"]
        containers_data = payload["containers"]

        now = timezone.now()
        with transaction.atomic():
            host.os_distro = os_distro
            host.os_version = os_version
            host.is_os_eol = eol
            host.os_eol_date = distro_eol_date(os_distro, os_version) if (os_distro and os_version) else None
            host.kernel_version = payload["kernel_version"]
            host.agent_version = payload["agent_version"]
            host.apt_lists_updated_at = _parse_timestamp(payload["apt_lists_updated_at"])
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
                            name=pkg["name"],
                            installed_version=pkg["installed_version"],
                            candidate_version=pkg["candidate_version"],
                            is_security_update=pkg["is_security_update"],
                            source_pocket=pkg["source_pocket"],
                        )
                        for pkg in packages_data
                    ]
                )

            _sync_containers(host, containers_data, now)

        # Spec §6.4: live verification runs after every agent report. grace_eval runs verify_findings in the
        # worker; unique=True collapses the reports of all hosts into one pending run.
        enqueue("grace_eval", unique=True)

        return Response(
            {
                "status": "ok",
                "hostname": host.hostname,
                "is_os_eol": host.is_os_eol,
            },
            status=status.HTTP_200_OK,
        )

