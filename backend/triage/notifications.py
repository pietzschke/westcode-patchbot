"""Slack notifications (spec v2.1 §6.6): aggregated DMs and idempotent escalations.

- one DM per assignee per run, listing every new finding with an „Ich bin dran“ button (plus a one-time
  notice for IN_PROGRESS findings whose target version was raised);
- unassigned findings go to the team channel;
- each escalation stage is posted exactly once, only on working days 08:00–18:00
  (KEV-listed CRITICAL findings immediately);
- NotificationLog makes every send idempotent (NEW DMs once per NEW cycle, keyed by
  ``discovered_at``); failures are retried next run.
"""

from __future__ import annotations

import logging
import zlib
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from inventory.models import TeamMember
from triage.clock import next_posting_time, uses_wall_clock
from triage.findings import log_event
from triage.models import OPEN_STATES, Finding, IntegrationHealth, NotificationLog
from triage.slack import SlackError

logger = logging.getLogger(__name__)

STAGE_BY_STATE = {"NEW": 1, "IN_PROGRESS": 2, "PR_MERGED_WAITING_LIVE": 3}
STAGE_LABEL = {1: "nicht bestätigt", 2: "Umsetzungsfrist überschritten", 3: "nach Merge noch nicht live"}
RENOVATE_MAX_AGE = timedelta(hours=26)


def record_health(name: str, ok: bool, error: str = "", now: datetime | None = None) -> None:
    IntegrationHealth.objects.update_or_create(
        name=name, defaults={"ok": ok, "last_error": "" if ok else error[:1000], "checked_at": now or timezone.now()}
    )


def _pr_ci_suffix(f: Finding) -> str:
    if f.ci_status != "failure":
        return ""
    if f.pr_source == "BOT":
        ref = f"<{f.pr_url}|Renovate-PR #{f.pr_number}>" if (f.pr_url and f.pr_number) else "Renovate-PR"
        return f" · ⚠️ {ref} durch rote CI blockiert"
    if f.pr_number:
        ref = f"<{f.pr_url}|PR #{f.pr_number}>" if f.pr_url else f"PR #{f.pr_number}"
        return f" · ⚠️ {ref}: rote CI"
    return ""


def _finding_line(f: Finding) -> str:
    kind = "Einfacher Fix" if f.complexity == "SIMPLE" else "Komplexer Eingriff"
    deadline = timezone.localtime(f.deadline_at).strftime("%d.%m. %H:%M") if f.deadline_at else "–"
    if f.package_name == "__os_eol__":
        return f"*{f.project.name}* · {f.display_title} ({f.highest_severity}) · {kind} · Frist {deadline}"
    cves = ", ".join(f.vulnerability_ids[:2]) or f.package_name
    return (
        f"*{f.project.name}* · `{f.package_name}` → {f.target_version or '–'} · {cves} ({f.highest_severity}) "
        f"· {kind} · Frist {deadline}{_pr_ci_suffix(f)}"
    )


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


def _target_stage(finding: Finding) -> int:
    """TARGET_RAISED dedup key: one notice per (finding, target_version)."""
    return zlib.crc32(finding.target_version.encode()) & 0x7FFFFFFF


def _recipient(f: Finding) -> str:
    return f.assignee.slack_user_id if f.assignee and f.assignee.slack_user_id else settings.SLACK_TEAM_CHANNEL_ID


def send_new_finding_dms(*, slack, now: datetime | None = None, target_raised: Iterable[Finding] = ()) -> int:
    """One aggregated message per recipient: new findings, IN_PROGRESS findings whose target version
    was raised by this scan (spec §5.3), plus open Renovate PRs whose CI turned red after the initial DM."""
    now = now or timezone.now()
    already = set(NotificationLog.objects.filter(kind="NEW_DM").values_list("finding_id", "stage"))
    pending = [
        f
        for f in Finding.objects.filter(state="NEW").select_related("project", "assignee")
        if (f.id, _new_cycle_stage(f)) not in already
    ]
    pending_ids = {f.id for f in pending}
    raised_logged = set(NotificationLog.objects.filter(kind="TARGET_RAISED").values_list("finding_id", "stage"))
    raised_pending = list({
        f.id: f for f in target_raised if f.state == "IN_PROGRESS" and (f.id, _target_stage(f)) not in raised_logged
    }.values())
    ci_logged = set(NotificationLog.objects.filter(kind="BOT_CI_FAILED").values_list("finding_id", "stage"))
    ci_blocked = [
        f
        for f in Finding.objects.filter(
            state__in=("NEW", "IN_PROGRESS"), pr_source="BOT", ci_status="failure", pr_number__isnull=False
        ).select_related("project", "assignee")
        if f.id not in pending_ids and (f.id, int(f.pr_number)) not in ci_logged
    ]

    groups: dict[str, list[Finding]] = defaultdict(list)
    raised_groups: dict[str, list[Finding]] = defaultdict(list)
    ci_groups: dict[str, list[Finding]] = defaultdict(list)
    for f in pending:
        groups[_recipient(f)].append(f)
    for f in raised_pending:
        raised_groups[_recipient(f)].append(f)
    for f in ci_blocked:
        ci_groups[_recipient(f)].append(f)

    sent = failed = 0
    for recipient in list(dict.fromkeys([*groups, *raised_groups, *ci_groups])):
        findings = groups.get(recipient, [])
        raised = raised_groups.get(recipient, [])
        blocked = ci_groups.get(recipient, [])
        to_team = recipient == settings.SLACK_TEAM_CHANNEL_ID
        parts = []
        if findings and to_team:
            reasons = "; ".join(sorted({f.assigned_reason_de for f in findings if f.assigned_reason_de}))
            parts.append(f"⚠️ {len(findings)} neue Sicherheits-Aufgabe(n) ohne zuständige Person"
                         + (f" ({reasons})" if reasons else ""))
        elif findings:
            parts.append(f"🔐 {len(findings)} neue Sicherheits-Aufgabe(n) für dich")
        if raised:
            parts.append(f"⬆️ Zielversion bei {len(raised)} Aufgabe(n) in Bearbeitung angehoben")
        if blocked:
            parts.append(f"⚠️ Auto-Merge bei {len(blocked)} Renovate-Security-PR(s) durch rote CI blockiert")
        text = " · ".join(parts)
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{text}*"}}]
        for f in findings:
            blocks += _finding_blocks(f)
        for f in raised:
            blocks += _finding_blocks(f, f"⬆️ Zielversion angehoben – bitte Fix auf {f.target_version} anpassen: "
                                         f"{_finding_line(f)}")
        for f in blocked:
            blocks += _finding_blocks(f, f"⚠️ Auto-Merge durch rote CI blockiert: {_finding_line(f)}")
        try:
            ts = slack.post_message(recipient, text, blocks)
        except SlackError as exc:
            logger.warning("Slack DM to %s failed: %s", recipient, exc)
            record_health("slack", False, str(exc), now)
            failed += 1
            continue
        for f in findings:
            _log_sent([f], "NEW_DM", _new_cycle_stage(f), recipient, ts, now)
            if f.pr_source == "BOT" and f.ci_status == "failure" and f.pr_number is not None:
                _log_sent([f], "BOT_CI_FAILED", int(f.pr_number), recipient, ts, now)
        for f in raised:
            _log_sent([f], "TARGET_RAISED", _target_stage(f), recipient, ts, now)
        for f in blocked:
            _log_sent([f], "BOT_CI_FAILED", int(f.pr_number), recipient, ts, now)
        sent += 1
    if sent and not failed:  # a later success must not hide an earlier failure of the same run
        record_health("slack", True, now=now)
    return sent


def escalate_overdue(*, slack, now: datetime | None = None) -> int:
    now = now or timezone.now()
    in_window = next_posting_time(now) == now
    posted = failed = 0
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
            failed += 1
            continue
        f.escalated_stage = stage
        f.save(update_fields=["escalated_stage", "updated_at"])
        _log_sent([f], "ESCALATION", stage, settings.SLACK_TEAM_CHANNEL_ID, ts, now)
        log_event(f, source="SYSTEM", from_state=f.state, to_state=f.state, at=now,
                  note=f"Eskaliert an den Team-Channel ({STAGE_LABEL[stage]}).")
        posted += 1
    if posted and not failed:
        record_health("slack", True, now=now)
    return posted


def sync_slack_user_ids(*, slack) -> int:
    updated = looked_up = 0
    for member in TeamMember.objects.filter(is_active=True, slack_user_id__isnull=True):
        try:
            user_id = slack.lookup_user_by_email(member.email)
        except SlackError as exc:
            record_health("slack", False, str(exc))
            return updated
        looked_up += 1
        if user_id:
            member.slack_user_id = user_id
            member.save(update_fields=["slack_user_id"])
            updated += 1
    if looked_up:  # the Slack API answered every lookup: clear an earlier failure (DMs re-record their own)
        record_health("slack", True)
    return updated


def _post_system_alert(*, slack, kind: str, stage: int, text: str, now: datetime) -> None:
    channel = getattr(settings, "SLACK_TEAM_CHANNEL_ID", "")
    if slack is None or not channel:
        return
    if NotificationLog.objects.filter(finding__isnull=True, kind=kind, stage=stage, recipient=channel).exists():
        return
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    try:
        ts = slack.post_message(channel, text, blocks)
    except SlackError as exc:
        logger.warning("System Slack alert (%s) failed: %s", kind, exc)
        record_health("slack", False, str(exc), now)
        return
    NotificationLog.objects.create(finding=None, kind=kind, stage=stage, recipient=channel, slack_ts=ts, sent_at=now)
    record_health("slack", True, now=now)


def check_renovate_health(*, github, slack=None, now: datetime | None = None) -> bool | None:
    """Mirror the central Renovate GitHub Actions runner into IntegrationHealth („renovate“) and alert once on failure."""
    now = now or timezone.now()
    repo = getattr(settings, "PATCHBOT_RENOVATE_REPO", "")
    branch = getattr(settings, "PATCHBOT_RENOVATE_BRANCH", "main")
    if not repo or github is None or not hasattr(github, "latest_workflow_check"):
        return None
    try:
        check = github.latest_workflow_check(repo, branch, "renovate")
    except Exception as exc:  # noqa: BLE001 - record integration failure without crashing reconciliation
        logger.warning("Renovate health check on %s failed: %s", repo, exc)
        record_health("renovate", False, f"Renovate-Status auf {repo} nicht abrufbar: {exc}", now)
        return False
    if check is None:
        return None
    if check.get("status") == "missing":
        record_health("renovate", False, f"Kein abgeschlossener Renovate-Lauf auf {repo}@{branch} gefunden.", now)
        return False

    run_id = int(check.get("id") or 0) & 0x7FFFFFFF
    url = str(check.get("html_url") or "")
    conclusion = str(check.get("conclusion") or "")
    if conclusion != "success":
        record_health("renovate", False, f"Letzter Renovate-Lauf fehlgeschlagen ({conclusion}). {url}".strip(), now)
        link = f"<{url}|Workflow-Logs öffnen>" if url else conclusion
        _post_system_alert(
            slack=slack,
            kind="RENOVATE_FAILURE",
            stage=run_id,
            text=f"❌ *Renovate-Runner fehlgeschlagen* (`{repo}`): {link}",
            now=now,
        )
        return False

    completed_at = parse_datetime(str(check.get("completed_at") or ""))
    if completed_at is not None and now - completed_at > RENOVATE_MAX_AGE:
        hours = int((now - completed_at).total_seconds() // 3600)
        record_health("renovate", False, f"Letzter erfolgreicher Renovate-Lauf auf {repo} ist {hours} h alt.", now)
        if next_posting_time(now) == now:
            _post_system_alert(
                slack=slack,
                kind="RENOVATE_STALE",
                stage=run_id,
                text=f"⚠️ *Renovate-Runner überfällig* (`{repo}`): letzter erfolgreicher Lauf vor {hours} h.",
                now=now,
            )
        return False

    record_health("renovate", True, now=now)
    return True
