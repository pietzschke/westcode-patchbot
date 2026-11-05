"""Finding state machine (spec v2.1 §6.2). Every transition writes a FindingEvent."""

from __future__ import annotations

from datetime import datetime

from django.db import transaction
from django.utils import timezone

from triage.clock import deadline_for
from triage.findings import _start_new, log_event
from triage.models import OPEN_STATES, Finding
from triage.notifications import STAGE_BY_STATE

MIN_REASON_LENGTH = 15


class InvalidTransition(Exception):
    pass


def _deadline(finding: Finding, stage: str, start: datetime) -> datetime:
    return deadline_for(
        stage=stage,
        complexity=finding.complexity,
        severity=finding.highest_severity,
        kev_listed=finding.kev_listed,
        start=start,
    )


def _move(finding: Finding, to_state: str, *, actor=None, source: str, note: str = "", now: datetime) -> None:
    previous = finding.state
    finding.state = to_state
    finding.save()
    log_event(finding, actor=actor, source=source, from_state=previous, to_state=to_state, note=note, at=now)


@transaction.atomic
def acknowledge(finding: Finding, actor, *, source: str, now: datetime | None = None) -> Finding:
    now = now or timezone.now()
    if actor is None or not actor.is_active:
        raise InvalidTransition("Only active team members can acknowledge findings.")
    if finding.state not in ("NEW", "IN_PROGRESS"):
        raise InvalidTransition(f"Cannot acknowledge a finding in state {finding.state}.")

    if finding.assignee_id != actor.id:
        previous_name = finding.assignee.name if finding.assignee else "niemandem"
        finding.assignee = actor
        finding.assigned_reason_de = "Per „Ich bin dran“ übernommen"
        log_event(finding, actor=actor, source=source, from_state=finding.state, to_state=finding.state,
                  note=f"{actor.name} hat die Aufgabe von {previous_name} übernommen.", at=now)

    if finding.state == "NEW":
        finding.acknowledged_at = now
        finding.deadline_at = _deadline(finding, "IN_PROGRESS", now)
        finding.extended_in_stage = ""
        _move(finding, "IN_PROGRESS", actor=actor, source=source, note="„Ich bin dran“", now=now)
    else:
        finding.save()
    return finding


@transaction.atomic
def mark_pr_merged(
    finding: Finding,
    *,
    merge_commit_sha: str,
    merged_at: datetime,
    source: str,
    note: str = "",
    now: datetime | None = None,
) -> Finding:
    now = now or timezone.now()
    if finding.state == "PR_MERGED_WAITING_LIVE" and finding.merge_commit_sha == merge_commit_sha:
        return finding
    if finding.state not in ("NEW", "IN_PROGRESS"):
        raise InvalidTransition(f"Cannot mark a merge for a finding in state {finding.state}.")

    if finding.state == "NEW":
        finding.acknowledged_at = merged_at
        log_event(finding, source=source, from_state="NEW", to_state="NEW",
                  note="Implizit bestätigt: Fix wurde vor „Ich bin dran“ gemergt.", at=now)
    finding.merge_commit_sha = merge_commit_sha
    finding.pr_merged_at = merged_at
    finding.extended_in_stage = ""

    repository = finding.repository
    if repository is not None and repository.deployment_mode == "NONE":
        finding.verified_live_at = None
        _move(finding, "RESOLVED_NO_DEPLOYMENT", source=source,
              note=note or "Gemergt; Repository wird nicht deployt.", now=now)
    else:
        finding.deadline_at = _deadline(finding, "PR_MERGED_WAITING_LIVE", merged_at)
        _move(finding, "PR_MERGED_WAITING_LIVE", source=source,
              note=note or f"Fix gemergt ({merge_commit_sha[:12]}), warte auf Live-Gang.", now=now)
    return finding


NO_DEPLOYMENT_NOTE = "Repository wird nicht deployt (Deployment-Art „keine“) – kein Live-Gang nötig."


@transaction.atomic
def resolve_without_deployment(repository, *, source: str, actor=None, now: datetime | None = None) -> list[Finding]:
    """Close merged findings of a repository that is not deployed (spec §6.2: deployment_mode = NONE)."""
    now = now or timezone.now()
    if repository is None or repository.deployment_mode != "NONE":
        return []
    resolved = []
    for finding in Finding.objects.select_for_update().filter(repository=repository, state="PR_MERGED_WAITING_LIVE"):
        finding.verified_live_at = None
        _move(finding, "RESOLVED_NO_DEPLOYMENT", actor=actor, source=source, note=NO_DEPLOYMENT_NOTE, now=now)
        resolved.append(finding)
    return resolved


def mark_fix_detected_on_branch(finding: Finding, *, commit_sha: str, now: datetime | None = None) -> Finding:
    now = now or timezone.now()
    return mark_pr_merged(
        finding,
        merge_commit_sha=commit_sha,
        merged_at=now,
        source="SYSTEM",
        note=f"Fix ohne Patchbot-PR auf dem Default-Branch erkannt ({commit_sha[:12]}).",
        now=now,
    )


@transaction.atomic
def extend_deadline(finding: Finding, actor, *, reason: str, now: datetime | None = None) -> Finding:
    now = now or timezone.now()
    reason = (reason or "").strip()
    if len(reason) < MIN_REASON_LENGTH:
        raise ValueError(f"Reason must have at least {MIN_REASON_LENGTH} characters.")
    if finding.state not in OPEN_STATES:
        raise InvalidTransition(f"Cannot extend a finding in state {finding.state}.")
    if finding.extended_in_stage == finding.state:
        raise InvalidTransition("The deadline was already extended in this stage.")
    # Extend from now when already overdue — otherwise the one allowed extension could still be in the past.
    start = max(finding.deadline_at, now) if finding.deadline_at else now
    finding.deadline_at = _deadline(finding, finding.state, start)
    finding.extended_in_stage = finding.state
    # The stage was already escalated: re-arm it so the extended deadline can escalate once more.
    stage = STAGE_BY_STATE[finding.state]
    if finding.escalated_stage == stage:
        finding.escalated_stage = stage - 1
    finding.save()
    log_event(finding, actor=actor, source="WEB", from_state=finding.state, to_state=finding.state,
              note=f"Frist verlängert: {reason}", at=now)
    return finding


def on_monitoring_changed(sender, project, monitored: bool, source: str = "SYSTEM", **kwargs) -> None:
    now = timezone.now()
    with transaction.atomic():
        if not monitored:
            for finding in Finding.objects.select_for_update().filter(project=project, state__in=OPEN_STATES):
                _move(finding, "SUPPRESSED_UNMONITORED", source=source,
                      note="Projekt wird nicht mehr überwacht.", now=now)
            return
        for finding in Finding.objects.select_for_update().filter(project=project, state="SUPPRESSED_UNMONITORED"):
            previous = finding.state
            _start_new(finding, now)
            finding.save()
            log_event(finding, source=source, from_state=previous, to_state="NEW",
                      note="Projekt wird wieder überwacht.", at=now)
