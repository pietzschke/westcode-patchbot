"""Dismiss/snooze with mandatory reason, transparency post and automatic reopen rules (spec v2.1 §6.5)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from triage.findings import clear_dismissal, log_event, reopen_state
from triage.models import OPEN_STATES, SEVERITY_RANK, Finding
from triage.slack import SlackError

logger = logging.getLogger(__name__)

MIN_REASON_LENGTH = 15
SNOOZE_DAYS = (14, 30)
DISMISSAL_REVIEW_AFTER = timedelta(days=180)
TRANSPARENCY_SEVERITIES = {"HIGH", "CRITICAL"}
REOPENABLE_STATES = ("DISMISSED", "SNOOZED", "FILTERED_IRRELEVANT")


def _transparency_post(finding: Finding, actor, mode: str, reason: str, slack) -> None:
    verb = "als „nicht betroffen“ markiert" if mode == "DISMISSED" else "zurückgestellt"
    who = f"<@{actor.slack_user_id}>" if actor.slack_user_id else actor.name
    cves = ", ".join(finding.vulnerability_ids[:3]) or finding.package_name
    text = f"ℹ️ {who} hat {cves} ({finding.highest_severity}) in Projekt {finding.project.name} {verb}: „{reason}“"
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {"type": "actions", "elements": [{
            "type": "button", "action_id": "reopen", "value": str(finding.id),
            "text": {"type": "plain_text", "text": "Wieder öffnen"},
        }]},
    ]
    slack.post_message(settings.SLACK_TEAM_CHANNEL_ID, text, blocks)


@transaction.atomic
def dismiss(finding: Finding, actor, *, mode: str, reason: str, snooze_days: int = 14, source: str, slack,
            now: datetime | None = None) -> Finding:
    now = now or timezone.now()
    reason = (reason or "").strip()
    if len(reason) < MIN_REASON_LENGTH:
        raise ValidationError(f"Begründung muss mindestens {MIN_REASON_LENGTH} Zeichen haben.")
    if mode not in ("DISMISSED", "SNOOZED"):
        raise ValidationError("Modus muss DISMISSED oder SNOOZED sein.")
    if mode == "SNOOZED" and snooze_days not in SNOOZE_DAYS:
        raise ValidationError(f"Zurückstellen ist nur für {SNOOZE_DAYS} Tage möglich.")
    if finding.state not in OPEN_STATES:
        raise ValidationError(f"Ein Finding im Status {finding.state} kann nicht zurückgestellt werden.")

    previous = finding.state
    finding.state = mode
    finding.dismissal_mode = mode
    finding.dismissal_reason = reason
    finding.dismissed_by = actor
    finding.dismissed_at = now
    finding.dismissed_severity = finding.highest_severity
    finding.dismissed_kev_listed = finding.kev_listed
    finding.snoozed_until = now + timedelta(days=snooze_days) if mode == "SNOOZED" else None
    finding.save()
    label = "Nicht betroffen" if mode == "DISMISSED" else f"Zurückgestellt ({snooze_days} Tage)"
    log_event(finding, actor=actor, source=source, from_state=previous, to_state=mode, note=f"{label}: {reason}", at=now)

    if finding.highest_severity in TRANSPARENCY_SEVERITIES:
        try:
            _transparency_post(finding, actor, mode, reason, slack)
        except SlackError as exc:
            logger.warning("Transparency post for finding %s failed: %s", finding.id, exc)
            log_event(finding, source="SYSTEM", from_state=mode, to_state=mode, at=now,
                      note=f"Transparenz-Hinweis an den Team-Channel konnte nicht gesendet werden: {exc}")
    return finding


@transaction.atomic
def reopen(finding: Finding, actor, *, source: str, note: str, now: datetime | None = None) -> Finding:
    now = now or timezone.now()
    if finding.state not in REOPENABLE_STATES:
        raise ValidationError(f"Ein Finding im Status {finding.state} kann nicht wieder geöffnet werden.")
    previous = finding.state
    clear_dismissal(finding)
    reopen_state(finding, now)
    finding.save()
    log_event(finding, actor=actor, source=source, from_state=previous, to_state=finding.state, note=note, at=now)
    return finding


def _reopen_reason(finding: Finding, now: datetime) -> str | None:
    if finding.state == "SNOOZED":
        if finding.snoozed_until and finding.snoozed_until <= now:
            return "Zurückstellung abgelaufen."
        return None
    if SEVERITY_RANK.get(finding.highest_severity, 0) > SEVERITY_RANK.get(finding.dismissed_severity, 0):
        return f"Schweregrad auf {finding.highest_severity} gestiegen."
    if finding.kev_listed and not finding.dismissed_kev_listed:
        return "Schwachstelle wird inzwischen aktiv ausgenutzt (CISA KEV)."
    if finding.dismissed_at and now - finding.dismissed_at >= DISMISSAL_REVIEW_AFTER:
        return "Regelmäßige Überprüfung nach 180 Tagen."
    return None


def evaluate_reopen_rules(*, now: datetime | None = None) -> list[Finding]:
    now = now or timezone.now()
    reopened = []
    for finding in Finding.objects.filter(state__in=("SNOOZED", "DISMISSED")):
        reason = _reopen_reason(finding, now)
        if reason:
            reopen(finding, None, source="SYSTEM", note=reason, now=now)
            reopened.append(finding)
    return reopened
