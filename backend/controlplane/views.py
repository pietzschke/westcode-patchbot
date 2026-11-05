"""Control plane REST API (spec v2.1 §6, §7.1, §8).

Every action uses the TeamMember behind the session as actor; actor fields in
request bodies are ignored. Admin-only endpoints use IsTeamAdmin.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from controlplane.ampel import compute_ampel
from controlplane.clients import slack_client
from controlplane.serializers import (
    container_ref, finding_detail, finding_summary, host_ref, maintenance_dict, member_dict, project_dict,
    repository_dict, scan_run_dict,
)
from fleet.models import Host, HostContainer
from inventory.matching import confirm_suggestion
from inventory.models import LAYER_CHOICES, Project, RepositoryAsset, TeamMember
from inventory.notion_sync import set_monitoring
from inventory.permissions import IsTeamAdmin, IsTeamMember, active_member
from research.models import MaintenanceUpdate, ScanRun
from triage.dismissal import dismiss, reopen
from triage.jobs import ACTIVE as JOB_ACTIVE
from triage.jobs import enqueue
from triage.lifecycle import InvalidTransition, acknowledge, extend_deadline, resolve_without_deployment
from triage.models import Finding, Job

ASSET_MODELS = {"repository": RepositoryAsset, "host": Host, "container": HostContainer}
DEPLOYMENT_MODES = {value for value, _ in RepositoryAsset.DEPLOYMENT_MODES}


def _errors(exc: ValidationError) -> dict:
    return {"detail": exc.message_dict if hasattr(exc, "error_dict") else exc.messages}


class DashboardView(APIView):
    def get(self, request: Request) -> Response:
        now = timezone.now()
        findings = Finding.objects.select_related("project", "assignee")
        open_ = findings.filter(state__in=("NEW", "IN_PROGRESS")).order_by("deadline_at")
        return Response({
            "ampel": compute_ampel(now=now),
            "buckets": {
                "simple": [finding_summary(f, now) for f in open_.filter(complexity="SIMPLE")],
                "complex": [finding_summary(f, now) for f in open_.exclude(complexity="SIMPLE")],
                "waiting_live": [finding_summary(f, now) for f in findings.filter(state="PR_MERGED_WAITING_LIVE")],
            },
            "filtered": [finding_summary(f, now) for f in findings.filter(state="FILTERED_IRRELEVANT")[:200]],
            "maintenance": [maintenance_dict(u) for u in MaintenanceUpdate.objects.select_related("project", "repository")],
            "me_id": active_member(request).id,
        })


class FindingDetailView(APIView):
    def get(self, request: Request, finding_id: int) -> Response:
        finding = get_object_or_404(Finding.objects.select_related("project", "assignee"), id=finding_id)
        return Response(finding_detail(finding))


class AcknowledgeView(APIView):
    def post(self, request: Request, finding_id: int) -> Response:
        finding = get_object_or_404(Finding, id=finding_id)
        try:
            acknowledge(finding, active_member(request), source="WEB")
        except InvalidTransition as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        return Response(finding_detail(finding))


class DismissView(APIView):
    def post(self, request: Request, finding_id: int) -> Response:
        finding = get_object_or_404(Finding.objects.select_related("project"), id=finding_id)
        mode = str(request.data.get("mode", ""))
        raw_days = request.data.get("snooze_days")
        snooze_days = 14
        if mode == "SNOOZED" and raw_days is not None:  # only snoozing uses it; clients may send null
            try:
                snooze_days = int(raw_days)
            except (TypeError, ValueError):
                return Response({"detail": "snooze_days muss eine Zahl sein."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            dismiss(finding, active_member(request), mode=mode,
                    reason=str(request.data.get("reason", "")), snooze_days=snooze_days, source="WEB",
                    slack=slack_client())
        except ValidationError as exc:
            return Response(_errors(exc), status=status.HTTP_400_BAD_REQUEST)
        return Response(finding_detail(finding))


class ReopenView(APIView):
    def post(self, request: Request, finding_id: int) -> Response:
        finding = get_object_or_404(Finding, id=finding_id)
        note = str(request.data.get("note", "")).strip() or "Im Web wieder geöffnet."
        try:
            reopen(finding, active_member(request), source="WEB", note=note)
        except ValidationError as exc:
            return Response(_errors(exc), status=status.HTTP_409_CONFLICT)
        return Response(finding_detail(finding))


class ExtendView(APIView):
    def post(self, request: Request, finding_id: int) -> Response:
        finding = get_object_or_404(Finding, id=finding_id)
        try:
            extend_deadline(finding, active_member(request), reason=str(request.data.get("reason", "")))
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except InvalidTransition as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        return Response(finding_detail(finding))


class MaintenanceAnalysisView(APIView):
    def post(self, request: Request, update_id: int) -> Response:
        update = get_object_or_404(MaintenanceUpdate, id=update_id)
        enqueue("maintenance_analysis", {"id": update.id, "requested_by": active_member(request).id})
        return Response(status=status.HTTP_202_ACCEPTED)


class ProjectsView(APIView):
    def get(self, request: Request) -> Response:
        projects = Project.objects.select_related("owner").prefetch_related(
            "repositories", "hosts", "containers__host")
        return Response({
            "projects": [project_dict(p) for p in projects],
            "unassigned_assets": {
                "repositories": [repository_dict(r) for r in RepositoryAsset.objects.filter(project__isnull=True, is_archived=False)
                                 .select_related("suggested_project")],
                "hosts": [host_ref(h) for h in Host.objects.filter(project__isnull=True).select_related("suggested_project")],
                "containers": [container_ref(c) for c in HostContainer.objects.filter(project__isnull=True)
                               .select_related("host", "suggested_project")],
            },
        })


class NotionSyncView(APIView):
    permission_classes = [IsTeamAdmin]

    def post(self, request: Request) -> Response:
        job = enqueue("notion_sync", {"trigger": "MANUAL"}, unique=True)
        return Response(status=status.HTTP_202_ACCEPTED if job else status.HTTP_409_CONFLICT)


class MonitoringView(APIView):
    permission_classes = [IsTeamAdmin]

    def post(self, request: Request, slug: str) -> Response:
        project = get_object_or_404(Project, slug=slug)
        monitored = request.data.get("monitored")
        if not isinstance(monitored, bool):
            return Response({"detail": "monitored muss true oder false sein."}, status=status.HTTP_400_BAD_REQUEST)
        set_monitoring(project, monitored, source="WEB")
        return Response(project_dict(project))


def _propagate_repository_project(asset) -> None:
    """Containers built from a repository follow its project unless they were assigned explicitly (review H-9).

    The OCI-source link may have been made while the repository had no project yet; without this the
    container would stay unassigned and its running image would never be scanned.
    """
    if isinstance(asset, RepositoryAsset) and asset.project_id is not None:
        HostContainer.objects.filter(repository=asset, project__isnull=True).update(project_id=asset.project_id)


def _asset(asset_type: str, asset_id: int):
    model = ASSET_MODELS.get(asset_type)
    if model is None:
        return None
    return model.objects.filter(id=asset_id).first()


class AssetConfirmView(APIView):
    permission_classes = [IsTeamAdmin]

    def post(self, request: Request, asset_type: str, asset_id: int) -> Response:
        asset = _asset(asset_type, asset_id)
        if asset is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        try:
            with transaction.atomic():
                confirm_suggestion(asset)
                _propagate_repository_project(asset)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"id": asset.id, "project": asset.project.slug if asset.project else None})


class AssetAssignView(APIView):
    permission_classes = [IsTeamAdmin]

    def post(self, request: Request, asset_type: str, asset_id: int) -> Response:
        asset = _asset(asset_type, asset_id)
        if asset is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        slug = request.data.get("project_slug")
        project = None
        if slug:
            project = Project.objects.filter(slug=slug).first()
            if project is None:
                return Response({"detail": "Unbekanntes Projekt."}, status=status.HTTP_400_BAD_REQUEST)
        asset.project = project
        asset.suggested_project = None
        with transaction.atomic():
            asset.save(update_fields=["project", "suggested_project"])
            _propagate_repository_project(asset)
        return Response({"id": asset.id, "project": slug or None})


class RepositoryView(APIView):
    permission_classes = [IsTeamAdmin]

    def patch(self, request: Request, repo_id: int) -> Response:
        repo = get_object_or_404(RepositoryAsset, id=repo_id)
        mode = request.data.get("deployment_mode")
        if mode not in DEPLOYMENT_MODES:
            return Response({"detail": f"deployment_mode muss einer von {sorted(DEPLOYMENT_MODES)} sein."},
                            status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            repo.deployment_mode = mode
            repo.save(update_fields=["deployment_mode"])
            # Merged fixes of a repository that is never deployed cannot go live: close them now.
            resolve_without_deployment(repo, source="WEB", actor=active_member(request))
        return Response(repository_dict(repo))


MEMBER_FIELDS = ("name", "email", "github_username", "git_commit_emails", "slack_user_id", "layers",
                 "is_default_infra_owner", "is_admin", "is_active")


def _commit_emails(value) -> list[str]:
    """Git author addresses used for blame-based ownership: a de-duplicated, lower-cased list."""
    if not isinstance(value, list) or not all(isinstance(e, str) and "@" in e.strip() for e in value):
        raise ValidationError({"git_commit_emails": "Erwartet wird eine Liste von E-Mail-Adressen."})
    return list(dict.fromkeys(e.strip().lower() for e in value))


def _apply_member(member: TeamMember, data) -> None:
    for field in MEMBER_FIELDS:
        if field in data:
            value = data[field]
            if field in ("github_username", "slack_user_id") and value == "":
                value = None
            setattr(member, field, value)
    member.email = (member.email or "").strip().lower()
    if not member.email.endswith("@westcode.de"):
        raise ValidationError({"email": "Nur @westcode.de-Adressen sind erlaubt."})
    if not isinstance(member.layers, list) or not set(member.layers) <= set(LAYER_CHOICES):
        raise ValidationError({"layers": f"Erlaubt sind {list(LAYER_CHOICES)}."})
    member.git_commit_emails = _commit_emails(member.git_commit_emails)
    member.full_clean(exclude=["user"])
    member.save()


class TeamListView(APIView):
    def get_permissions(self):
        return [IsTeamAdmin()] if self.request.method == "POST" else [IsTeamMember()]

    def get(self, request: Request) -> Response:
        return Response([member_dict(m) for m in TeamMember.objects.all()])

    def post(self, request: Request) -> Response:
        member = TeamMember()
        try:
            with transaction.atomic():
                _apply_member(member, request.data)
        except ValidationError as exc:
            return Response(_errors(exc), status=status.HTTP_400_BAD_REQUEST)
        return Response(member_dict(member), status=status.HTTP_201_CREATED)


class TeamDetailView(APIView):
    permission_classes = [IsTeamAdmin]

    def patch(self, request: Request, member_id: int) -> Response:
        member = get_object_or_404(TeamMember, id=member_id)
        try:
            with transaction.atomic():
                _apply_member(member, request.data)
        except ValidationError as exc:
            return Response(_errors(exc), status=status.HTTP_400_BAD_REQUEST)
        return Response(member_dict(member))


class TeamTestDmView(APIView):
    permission_classes = [IsTeamAdmin]

    def post(self, request: Request, member_id: int) -> Response:
        member = get_object_or_404(TeamMember, id=member_id)
        enqueue("test_dm", {"member_id": member.id})
        return Response(status=status.HTTP_202_ACCEPTED)


class ScanRunView(APIView):
    def get(self, request: Request) -> Response:
        """Status for the header button: disabled while a daily scan job is queued or running (spec §8.1)."""
        job = Job.objects.filter(kind="daily_scan", status__in=JOB_ACTIVE).order_by("id").first()
        run = ScanRun.objects.first()
        return Response({
            "running": job is not None,
            "job_id": job.id if job else None,
            "scan_run": scan_run_dict(run) if run else None,
        })

    def post(self, request: Request) -> Response:
        job = enqueue("daily_scan", {"trigger": "MANUAL"}, unique=True)
        if job is None:
            return Response({"detail": "Ein Scan läuft bereits."}, status=status.HTTP_409_CONFLICT)
        return Response({"job_id": job.id}, status=status.HTTP_202_ACCEPTED)
