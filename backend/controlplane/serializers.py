"""Plain dict serializers for the control plane API."""

from __future__ import annotations

from datetime import datetime

from django.utils import timezone

from fleet.models import Host, HostContainer
from inventory.models import Project, RepositoryAsset, TeamMember
from research.models import MaintenanceUpdate, ScanRun
from triage.models import Finding
from triage.verification import needs_deployment_decision


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def member_ref(member: TeamMember | None) -> dict | None:
    return {"id": member.id, "name": member.name} if member else None


def project_ref(project: Project | None) -> dict | None:
    return {"slug": project.slug, "name": project.name} if project else None


def member_dict(m: TeamMember) -> dict:
    return {
        "id": m.id, "name": m.name, "email": m.email, "github_username": m.github_username,
        "git_commit_emails": m.git_commit_emails, "slack_user_id": m.slack_user_id, "layers": m.layers,
        "is_default_infra_owner": m.is_default_infra_owner, "is_admin": m.is_admin, "is_active": m.is_active,
    }


def finding_summary(f: Finding, now: datetime | None = None) -> dict:
    now = now or timezone.now()
    return {
        "id": f.id,
        "title": f"{f.package_name} {f.target_version}".strip(),
        "project": project_ref(f.project),
        "layer": f.layer,
        "target_ref": f.target_ref,
        "package_name": f.package_name,
        "current_version": f.current_version,
        "target_version": f.target_version,
        "vulnerability_ids": f.vulnerability_ids,
        "highest_severity": f.highest_severity,
        "kev_listed": f.kev_listed,
        "state": f.state,
        "complexity": f.complexity,
        "triage_status": f.triage_status,
        "assignee": member_ref(f.assignee),
        "deadline_at": _iso(f.deadline_at),
        "overdue": bool(f.deadline_at and f.deadline_at < now and f.is_open),
        "pr": {"number": f.pr_number, "url": f.pr_url, "draft": f.pr_is_draft, "source": f.pr_source,
               "ci_status": f.ci_status} if f.pr_number else None,
    }


def finding_detail(f: Finding) -> dict:
    data = finding_summary(f)
    data.update({
        "reachability": f.reachability,
        "confidence": f.confidence,
        "summary_de": f.summary_de,
        "breaking_changes_de": f.breaking_changes_de,
        "affected_files": f.affected_files,
        "assigned_reason_de": f.assigned_reason_de,
        "discovered_at": _iso(f.discovered_at),
        "acknowledged_at": _iso(f.acknowledged_at),
        "pr_merged_at": _iso(f.pr_merged_at),
        "verified_live_at": _iso(f.verified_live_at),
        "extended_in_stage": f.extended_in_stage,
        "dismissal": {"mode": f.dismissal_mode, "reason": f.dismissal_reason, "by": member_ref(f.dismissed_by),
                      "snoozed_until": _iso(f.snoozed_until)} if f.dismissal_mode else None,
        "manual_runbook": f.manual_runbook,
        "verification": f.verification_snapshot,
        "verification_checked_at": _iso(f.verification_checked_at),
        "needs_deployment_decision": needs_deployment_decision(f),
        "repository_id": f.repository_id,
        "events": [
            {"at": _iso(e.at), "actor": member_ref(e.actor), "source": e.source, "from_state": e.from_state,
             "to_state": e.to_state, "note": e.note}
            for e in f.events.select_related("actor").order_by("at", "id")
        ],
    })
    return data


def maintenance_dict(u: MaintenanceUpdate) -> dict:
    return {
        "id": u.id, "project": project_ref(u.project), "repository": u.repository.full_name,
        "package_name": u.package_name, "current_version": u.current_version, "target_version": u.target_version,
        "update_type": u.update_type, "pr_number": u.pr_number, "pr_url": u.pr_url, "ci_status": u.ci_status,
        "summary_de": u.summary_de,
    }


def project_dict(p: Project) -> dict:
    return {
        "slug": p.slug, "name": p.name, "customer_name": p.customer_name, "is_internal": p.is_internal,
        "notion_status": p.notion_status, "notion_missing": p.notion_missing, "is_monitored": p.is_monitored,
        "owner": member_ref(p.owner), "last_notion_synced_at": _iso(p.last_notion_synced_at),
        "repositories": [repository_dict(r) for r in p.repositories.all()],
        "hosts": [host_ref(h) for h in p.hosts.all()],
        "containers": [container_ref(c) for c in p.containers.all()],
        "open_findings": p.findings.filter(state__in=("NEW", "IN_PROGRESS", "PR_MERGED_WAITING_LIVE")).count(),
    }


def repository_dict(r: RepositoryAsset) -> dict:
    return {"id": r.id, "type": "repository", "name": r.full_name, "deployment_mode": r.deployment_mode,
            "is_archived": r.is_archived, "has_bot_updates": r.has_bot_updates,
            "suggested_project": project_ref(r.suggested_project)}


def host_ref(h: Host) -> dict:
    return {"id": h.id, "type": "host", "name": h.hostname, "suggested_project": project_ref(h.suggested_project)}


def container_ref(c: HostContainer) -> dict:
    return {"id": c.id, "type": "container", "name": f"{c.host.hostname}: {c.name}", "image": c.image_tag,
            "suggested_project": project_ref(c.suggested_project)}


def scan_run_dict(run: ScanRun) -> dict:
    return {"id": run.id, "status": run.status, "started_at": _iso(run.started_at),
            "finished_at": _iso(run.finished_at), "targets_done": run.targets.count()}
