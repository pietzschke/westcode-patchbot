import hashlib
import secrets
from typing import Any
from uuid import UUID

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from catalog.live_sync import run_live_sync
from catalog.models import ServiceGroup
from fleet.models import Host
from rollouts.models import RolloutPlan
from rollouts.orchestrator import create_rollout_plan, start_rollout_plan


def serialize_service_group(sg: ServiceGroup) -> dict[str, Any]:
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
                "target_type": ht.target_type,
                "working_dir": ht.working_dir,
                "compose_service": ht.compose_service,
                "running_version": ht.running_version,
                "target_version": ht.target_version,
                "git_clean": ht.git_clean,
            }
            for ht in sg.host_targets.select_related("host").all()
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


def serialize_rollout_plan(plan: RolloutPlan) -> dict[str, Any]:
    steps = plan.steps.select_related("host", "git_target", "agent_job").order_by("order")
    return {
        "id": str(plan.id),
        "service_group": plan.service_group.slug,
        "service_slug": plan.service_group.slug,
        "service_display_name": plan.service_group.display_name,
        "service_logo_key": plan.service_group.logo_key,
        "status": plan.status,
        "block_reason": plan.block_reason,
        "created_at": plan.created_at.isoformat(),
        "steps": [
            {
                "id": s.id,
                "order": s.order,
                "step_type": s.step_type,
                "status": s.status,
                "hostname": s.host.hostname if s.host else None,
                "host_slug": s.host.slug if s.host else None,
                "repo_full_name": s.git_target.repo_full_name if s.git_target else None,
                "pr_number": s.git_target.pr_number if s.git_target else None,
                "pr_url": s.git_target.pr_url if s.git_target else None,
                "working_dir": s.working_dir,
                "compose_service": s.compose_service,
                "target_version": s.target_version,
                "agent_job_id": str(s.agent_job_id) if s.agent_job_id else None,
                "result_payload": s.agent_job.result_payload if s.agent_job else None,
            }
            for s in steps
        ],
    }


def serialize_host(host: Host) -> dict[str, Any]:
    pkgs = list(host.packages.all())
    containers = list(host.containers.all())
    sec_count = sum(1 for p in pkgs if p.is_security_update)
    distro_str = f"{host.os_distro} {host.os_version}".strip() or (host.declared_image or "unbekannt")
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
        "is_eol": host.is_os_eol,
        "is_os_eol": host.is_os_eol,
        "reboot_required": host.reboot_required,
        "last_seen_at": host.last_seen_at.isoformat() if host.last_seen_at else None,
        "has_agent_token": bool(host.agent_token_hash),
        "pending_apt_count": len(pkgs),
        "security_apt_count": sec_count,
        "actionable_packages_count": len(pkgs),
        "container_count": len(containers),
        "containers_count": len(containers),
        "containers": [
            {
                "name": c.name,
                "image_tag": c.image_tag,
                "oci_title": c.oci_title,
                "oci_revision": c.oci_revision,
                "working_dir": c.working_dir,
                "compose_service": c.compose_service,
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
            }
            for p in pkgs
        ],
    }


class ServiceListView(APIView):
    authentication_classes = []
    permission_classes = []

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


class ServicePlanCreateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request: Request, slug: str) -> Response:
        sg = get_object_or_404(ServiceGroup, slug=slug)
        plan = create_rollout_plan(sg)
        return Response(
            serialize_rollout_plan(plan),
            status=status.HTTP_201_CREATED,
        )


class RolloutPlanListView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request: Request) -> Response:
        plans = RolloutPlan.objects.select_related("service_group").prefetch_related(
            "steps__host",
            "steps__git_target",
            "steps__agent_job",
        ).order_by("-created_at")[:50]
        return Response(
            [serialize_rollout_plan(p) for p in plans],
            status=status.HTTP_200_OK,
        )


class RolloutPlanDetailView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request: Request, plan_id: UUID) -> Response:
        plan = get_object_or_404(RolloutPlan.objects.select_related("service_group"), id=plan_id)
        return Response(
            serialize_rollout_plan(plan),
            status=status.HTTP_200_OK,
        )


class RolloutPlanExecuteView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request: Request, plan_id: UUID) -> Response:
        plan = get_object_or_404(RolloutPlan.objects.select_related("service_group"), id=plan_id)
        if plan.status != "READY":
            detail = (
                plan.block_reason
                if plan.block_reason
                else f"Cannot execute RolloutPlan {plan.id}: status is {plan.status}"
            )
            return Response(
                {"detail": detail, "plan": serialize_rollout_plan(plan)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        updated_plan = start_rollout_plan(plan)
        return Response(
            serialize_rollout_plan(updated_plan),
            status=status.HTTP_200_OK,
        )


class HostListView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request: Request) -> Response:
        hosts = Host.objects.prefetch_related("packages", "containers").all()
        return Response(
            [serialize_host(h) for h in hosts],
            status=status.HTTP_200_OK,
        )


class HostDetailView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request: Request, slug: str) -> Response:
        host = get_object_or_404(Host.objects.prefetch_related("packages", "containers"), slug=slug)
        return Response(serialize_host(host), status=status.HTTP_200_OK)


class HostTokenGenerateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request: Request, slug: str) -> Response:
        host = get_object_or_404(Host, slug=slug)
        raw_token = secrets.token_urlsafe(32)
        host.agent_token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        host.save(update_fields=["agent_token_hash"])
        base_url = request.build_absolute_uri("/").rstrip("/")
        install_cmd = f"sudo ./deploy/install-agent.sh {base_url} {raw_token} {host.hostname}"
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


class LiveSyncView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request: Request) -> Response:
        summary = run_live_sync()
        return Response(summary, status=status.HTTP_200_OK)
