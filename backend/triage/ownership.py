"""Ownership cascade (spec v2.1 §6.3)."""

from __future__ import annotations

from datetime import datetime, timedelta

from django.utils import timezone

from inventory.models import TeamMember
from triage.findings import log_event
from triage.models import Finding

BOT_LOGINS = {"dependabot", "renovate", "github-actions", "renovate-bot", "dependabot-preview"}
AUTHOR_LOOKBACK = timedelta(days=365)


def _is_bot(author: dict) -> bool:
    login = (author.get("login") or "").lower()
    email = (author.get("email") or "").lower()
    return login.endswith("[bot]") or login in BOT_LOGINS or "[bot]" in email


def _member_for_author(author: dict, members: list[TeamMember]) -> TeamMember | None:
    login = (author.get("login") or "").lower()
    email = (author.get("email") or "").lower()
    for member in members:
        aliases = {e.lower() for e in member.git_commit_emails or []}
        if (login and (member.github_username or "").lower() == login) or (
            email and (email == member.email or email in aliases)
        ):
            return member
    return None


def _project_owner(finding: Finding) -> tuple[TeamMember | None, str]:
    owner = finding.project.owner
    if owner is not None and owner.is_active:
        return owner, "Projekt-Owner laut Notion"
    return None, "Projekt hat keinen aktiven Owner in Notion"


def _candidate(finding: Finding, github, now: datetime) -> tuple[TeamMember | None, str]:
    if finding.layer == "INFRASTRUCTURE":
        infra = TeamMember.objects.filter(is_default_infra_owner=True, is_active=True).first()
        return (infra, "Infrastruktur-Owner") if infra else (None, "Kein Infrastruktur-Owner festgelegt")
    if finding.layer == "CONTAINER_IMAGE":
        return _project_owner(finding)

    # APPLICATION: manifest/lockfile bumps belong to the project owner; code changes to the last human author.
    paths = list(dict.fromkeys(f.split(":", 1)[0] for f in finding.affected_files or [] if f))
    if finding.complexity == "COMPLEX" and paths and finding.repository is not None:
        members = list(TeamMember.objects.filter(is_active=True))
        authors = github.recent_file_authors(finding.repository.full_name, paths, now - AUTHOR_LOOKBACK)
        for author in authors:
            if _is_bot(author):
                continue
            member = _member_for_author(author, members)
            if member is None:
                continue
            if member.slack_user_id:
                return member, f"Letzte Änderung an {paths[0]} (Git)"
            # Spec §6.3: an unreachable author is no owner → fall back to the project owner.
            owner, reason = _project_owner(finding)
            if owner is None:
                return None, reason
            return owner, f"Projekt-Owner ({member.name} hat keine Slack-ID hinterlegt)"
    return _project_owner(finding)


def resolve_assignee(finding: Finding, *, github, now: datetime | None = None) -> tuple[TeamMember | None, str]:
    member, reason = _candidate(finding, github, now or timezone.now())
    if member is None:
        return None, reason
    if not member.slack_user_id:
        return None, f"{member.name} hat keine Slack-ID hinterlegt"
    return member, reason


def _keeps_assignee(finding: Finding) -> bool:
    """An acknowledged finding („Ich bin dran“ or implicit) stays with its reachable assignee (spec §6.2)."""
    assignee = finding.assignee
    return (
        finding.acknowledged_at is not None
        and assignee is not None
        and assignee.is_active
        and bool(assignee.slack_user_id)
    )


def assign(finding: Finding, *, github, now: datetime | None = None) -> Finding:
    now = now or timezone.now()
    if _keeps_assignee(finding):
        return finding
    member, reason = resolve_assignee(finding, github=github, now=now)
    if finding.assignee_id == (member.id if member else None) and finding.assigned_reason_de == reason:
        return finding
    finding.assignee = member
    finding.assigned_reason_de = reason
    finding.save(update_fields=["assignee", "assigned_reason_de", "updated_at"])
    target = member.name if member else "niemanden (Team-Channel)"
    log_event(finding, source="SYSTEM", from_state=finding.state, to_state=finding.state,
              note=f"Zugewiesen an {target}: {reason}", at=now)
    return finding
