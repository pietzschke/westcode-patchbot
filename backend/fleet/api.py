from datetime import date
from uuid import UUID
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from fleet.auth import HostTokenAuthentication
from fleet.infra_sync import is_distro_eol
from fleet.models import AgentJob, Host, HostContainer, HostPackage

ALLOWED_JOB_RESULT_STATUSES = frozenset({"SUCCEEDED", "ROLLED_BACK", "FAILED"})


def _get_authenticated_host(request: Request) -> Host | None:
    if isinstance(request.auth, Host):
        return request.auth
    return None


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

        with transaction.atomic():
            host.os_distro = os_distro
            host.os_version = os_version
            host.is_os_eol = eol
            host.reboot_required = reboot_required
            host.last_seen_at = timezone.now()
            host.save(
                update_fields=[
                    "os_distro",
                    "os_version",
                    "is_os_eol",
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
                            candidate_version=str(pkg.get("candidate_version", "")),
                            is_security_update=bool(pkg.get("is_security_update", False)),
                        )
                        for pkg in packages_data
                    ]
                )

            host.containers.all().delete()
            if containers_data:
                HostContainer.objects.bulk_create(
                    [
                        HostContainer(
                            host=host,
                            container_id=str(c["container_id"]),
                            name=str(c["name"]),
                            image_tag=str(c.get("image_tag", "")),
                            image_id=str(c.get("image_id", "")),
                            repo_digests=list(c.get("repo_digests") or []),
                            oci_title=str(c.get("oci_title", "")),
                            oci_revision=str(c.get("oci_revision", "")),
                            working_dir=str(c.get("working_dir", "")),
                            compose_service=str(c.get("compose_service", "")),
                            git_clean=c.get("git_clean", None),
                            status=str(c.get("status", "running")),
                        )
                        for c in containers_data
                    ]
                )

        return Response(
            {
                "status": "ok",
                "hostname": host.hostname,
                "is_os_eol": host.is_os_eol,
            },
            status=status.HTTP_200_OK,
        )


class AgentNextJobView(APIView):
    authentication_classes = [HostTokenAuthentication]
    permission_classes = []

    def get(self, request: Request) -> Response:
        host = _get_authenticated_host(request)
        if host is None:
            return Response(
                {"detail": "Host authentication required."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        with transaction.atomic():
            job = (
                AgentJob.objects.filter(host=host, status="PENDING")
                .order_by("created_at", "id")
                .first()
            )
            if job is None:
                return Response({"id": None, "job": None}, status=status.HTTP_200_OK)

            job.status = "DISPATCHED"
            job.save(update_fields=["status"])

        return Response(
            {
                "id": str(job.id),
                "action_type": job.action_type,
                "payload": job.payload,
                "status": job.status,
                "created_at": job.created_at.isoformat(),
            },
            status=status.HTTP_200_OK,
        )


class AgentJobResultView(APIView):
    authentication_classes = [HostTokenAuthentication]
    permission_classes = []

    def post(self, request: Request, job_id: UUID) -> Response:
        host = _get_authenticated_host(request)
        if host is None:
            return Response(
                {"detail": "Host authentication required."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        job = AgentJob.objects.filter(id=job_id).first()
        if job is None:
            return Response(
                {"detail": "Job not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if job.host_id != host.id:
            return Response(
                {"detail": "Job does not belong to authenticated host."},
                status=status.HTTP_403_FORBIDDEN,
            )

        data = request.data if isinstance(request.data, dict) else {}
        raw_status = str(data.get("status", "") or "").strip().upper()
        if not raw_status and "ok" in data:
            raw_status = "SUCCEEDED" if bool(data["ok"]) else "FAILED"

        if raw_status not in ALLOWED_JOB_RESULT_STATUSES:
            return Response(
                {"detail": f"Invalid job status: {raw_status!r}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if "result_payload" in data and isinstance(data["result_payload"], dict):
            result_payload = data["result_payload"]
        else:
            result_payload = {k: v for k, v in data.items() if k != "status"}

        job.status = raw_status
        job.result_payload = result_payload
        job.save(update_fields=["status", "result_payload"])

        try:
            has_rollout_step = hasattr(job, "rollout_step") and job.rollout_step is not None
        except Exception:
            has_rollout_step = False
        if has_rollout_step:
            from rollouts.orchestrator import advance_rollout_on_job_result

            advance_rollout_on_job_result(job)

        return Response(
            {
                "id": str(job.id),
                "status": job.status,
                "result_payload": job.result_payload,
            },
            status=status.HTTP_200_OK,
        )
