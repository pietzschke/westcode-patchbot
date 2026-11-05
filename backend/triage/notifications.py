"""Slack notifications (spec v2.1 §6.6): aggregated DMs and idempotent escalations.

- one DM per assignee per run, listing every new finding with an „Ich bin dran“ button;
- unassigned findings go to the team channel;
- each escalation stage is posted exactly once, only on working days 08:00–18:00
  (KEV-listed CRITICAL findings immediately);
- NotificationLog makes every send idempotent (NEW DMs once per NEW cycle, keyed by
  ``discovered_at``); failures are retried next run.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from inventory.models import TeamMember
from triage.clock import next_posting_time, uses_wall_clock
from triage.findings import log_event
from triage.models import OPEN_STATES, Finding, IntegrationHealth, NotificationLog
from triage.slack import SlackError

logger = logging.getLogger(__name__)

STAGE_BY_STATE = {"NEW": 1, "IN_PROGRESS": 2, "PR_MERGED_WAITING_LIVE": 3}
STAGE_LABEL = {1: "nicht bestätigt", 2: "Umsetzungsfrist überschritten", 3: "nach Merge noch nicht live"}


def record_health(name: str, ok: bool, error: str = "", now: datetime | None = None) -> None:
    IntegrationHealth.objects.update_or_create(
        name=name, defaults={"ok": ok, "last_error": "" if ok else error[:1000], "checked_at": now or timezone.now()}
    )


def _finding_line(f: Finding) -> str:
    cves = ", ".join(f.vulnerability_ids[:2]) or f.package_name
    kind = "Einfacher Fix" if f.complexity == "SIMPLE" else "Komplexer Eingriff"
    deadline = timezone.localtime(f.deadline_at).strftime("%d.%m. %H:%M") if f.deadline_at else "–"
    return f"*{f.project.name}* · `{f.package_name}` → {f.target_version or '–'} · {cves} ({f.highest_severity}) · {kind} · Frist {deadline}"


ACKNOWLEDGEABLE_STATES = ("NEW", "IN_PROGRESS")


def _finding_blocks(f: Finding, text: str | None = None) -> list[dict]:
    """Section (``text`` or the finding line) plus buttons. Slack renders only the blocks when blocks are
    given, so everything the reader must see belongs into ``text``."""
    elements = []
    if f.state in ACKNOWLEDGEABLE_STATES:  # „Ich bin dran“ is rejected in any other state
        elements.append({"type": "button", "action_id": "ack", "value": str(f.id), "style": "primary",
                         "text": {"type": "plain_text", "text": "Ich bin dran"}})
    base_url = getattr(settings, "PATCHBOT_BASE_URL", "")
    if base_url:
        elements.append({"type": "button", "action_id": "details", "url": f"{base_url}/?finding={f.id}",
                         "text": {"type": "plain_text", "text": "Details"}})
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text or _finding_line(f)}}]
    if elements:
        blocks.append({"type": "actions", "block_id": f"finding-{f.id}", "elements": elements})
    return blocks


def _log_sent(findings: list[Finding], kind: str, stage: int, recipient: str, ts: str, now: datetime) -> None:
    for f in findings:
        try:
            with transaction.atomic():
                NotificationLog.objects.create(finding=f, kind=kind, stage=stage, recipient=recipient, slack_ts=ts, sent_at=now)
        except IntegrityError:
            pass


def _new_cycle_stage(finding: Finding) -> int:
    """NEW_DM dedup key: one DM per NEW cycle. Every (re)entry into NEW resets ``discovered_at``."""
    return int(finding.discovered_at.timestamp())


def send_new_finding_dms(*, slack, now: datetime | None = None) -> int:
    now = now or timezone.now()
    already = set(NotificationLog.objects.filter(kind="NEW_DM").values_list("finding_id", "stage"))
    pending = [
        f
        for f in Finding.objects.filter(state="NEW").select_related("project", "assignee")
        if (f.id, _new_cycle_stage(f)) not in already
    ]
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in pending:
        recipient = f.assignee.slack_user_id if f.assignee and f.assignee.slack_user_id else settings.SLACK_TEAM_CHANNEL_ID
        groups[recipient].append(f)

    sent = 0
    for recipient, findings in groups.items():
        to_team = recipient == settings.SLACK_TEAM_CHANNEL_ID
        if to_team:
            reasons = "; ".join(sorted({f.assigned_reason_de for f in findings if f.assigned_reason_de}))
            text = f"⚠️ {len(findings)} neue Sicherheits-Aufgabe(n) ohne zuständige Person" + (f" ({reasons})" if reasons else "")
        else:
            text = f"🔐 {len(findings)} neue Sicherheits-Aufgabe(n) für dich"
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{text}*"}}]
        for f in findings:
            blocks += _finding_blocks(f)
        try:
            ts = slack.post_message(recipient, text, blocks)
        except SlackError as exc:
            logger.warning("Slack DM to %s failed: %s", recipient, exc)
            record_health("slack", False, str(exc), now)
            continue
        for f in findings:
            _log_sent([f], "NEW_DM", _new_cycle_stage(f), recipient, ts, now)
        record_health("slack", True, now=now)
        sent += 1
    return sent


def escalate_overdue(*, slack, now: datetime | None = None) -> int:
    now = now or timezone.now()
    in_window = next_posting_time(now) == now
    posted = 0
    overdue = Finding.objects.filter(state__in=OPEN_STATES, deadline_at__lt=now).select_related("project", "assignee")
    for f in overdue:
        stage = STAGE_BY_STATE[f.state]
        if f.escalated_stage >= stage:
            continue
        if not (in_window or uses_wall_clock(f.highest_severity, f.kev_listed)):
            continue
        who = f"<@{f.assignee.slack_user_id}>" if f.assignee and f.assignee.slack_user_id else "niemand zugewiesen"
        text = f"⏰ Eskalation ({STAGE_LABEL[stage]}): {_finding_line(f)} · zuständig: {who}"
        try:
            ts = slack.post_message(settings.SLACK_TEAM_CHANNEL_ID, text, _finding_blocks(f, text))
        except SlackError as exc:
            record_health("slack", False, str(exc), now)
            continue
        f.escalated_stage = stage
        f.save(update_fields=["escalated_stage", "updated_at"])
        _log_sent([f], "ESCALATION", stage, settings.SLACK_TEAM_CHANNEL_ID, ts, now)
        log_event(f, source="SYSTEM", from_state=f.state, to_state=f.state, at=now,
                  note=f"Eskaliert an den Team-Channel ({STAGE_LABEL[stage]}).")
        record_health("slack", True, now=now)
        posted += 1
    return posted


def sync_slack_user_ids(*, slack) -> int:
    updated = 0
    for member in TeamMember.objects.filter(is_active=True, slack_user_id__isnull=True):
        try:
            user_id = slack.lookup_user_by_email(member.email)
        except SlackError as exc:
            record_health("slack", False, str(exc))
            return updated
        if user_id:
            member.slack_user_id = user_id
            member.save(update_fields=["slack_user_id"])
            updated += 1
    return updated
