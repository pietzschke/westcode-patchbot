"""Public webhook endpoints (spec v2.1 §3.3, §7.3, decision D-1).

Handlers only verify the signature, deduplicate and persist the event; the
worker processes it later and re-reads PR state from the GitHub API instead of
trusting the payload. Both endpoints fail closed without a configured secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime
from urllib.parse import parse_qs

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from inventory.models import TeamMember
from triage.dismissal import reopen
from triage.lifecycle import InvalidTransition, acknowledge, mark_pr_merged
from triage.models import Finding, WebhookEvent

logger = logging.getLogger(__name__)

SLACK_MAX_AGE_SECONDS = 300


def _valid_slack_signature(request: HttpRequest) -> bool:
    secret = settings.SLACK_SIGNING_SECRET
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    if not secret or not timestamp.isdigit() or not signature:
        return False
    if abs(time.time() - int(timestamp)) > SLACK_MAX_AGE_SECONDS:
        return False
    base = b"v0:" + timestamp.encode() + b":" + request.body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _valid_github_signature(request: HttpRequest) -> bool:
    secret = settings.GITHUB_WEBHOOK_SECRET
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not secret or not signature:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@csrf_exempt
@require_POST
def slack_interactions(request: HttpRequest) -> HttpResponse:
    if not _valid_slack_signature(request):
        return HttpResponse(status=401)
    try:
        payload = json.loads(parse_qs(request.body.decode("utf-8")).get("payload", ["{}"])[0])
    except (UnicodeDecodeError, json.JSONDecodeError):
        return HttpResponse(status=400)
    WebhookEvent.objects.create(source="SLACK", event_type=str(payload.get("type", "")), payload=payload,
                                received_at=timezone.now())
    return HttpResponse(status=200)


@csrf_exempt
@require_POST
def github_webhook(request: HttpRequest) -> HttpResponse:
    if not _valid_github_signature(request):
        return HttpResponse(status=401)
    delivery = request.headers.get("X-GitHub-Delivery", "") or None
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return HttpResponse(status=400)
    try:
        with transaction.atomic():
            WebhookEvent.objects.create(source="GITHUB", delivery_id=delivery,
                                        event_type=request.headers.get("X-GitHub-Event", ""), payload=payload,
                                        received_at=timezone.now())
    except IntegrityError:
        return HttpResponse("duplicate", status=200)
    return HttpResponse(status=202)


def _finish(event: WebhookEvent, status: str, error: str = "") -> None:
    event.status = status
    event.error = error[:2000]
    event.processed_at = timezone.now()
    event.save(update_fields=["status", "error", "processed_at"])


def _process_slack(event: WebhookEvent, now: datetime) -> None:
    payload = event.payload or {}
    user_id = str((payload.get("user") or {}).get("id", ""))
    member = TeamMember.objects.filter(slack_user_id=user_id, is_active=True).first() if user_id else None
    if member is None:
        return _finish(event, "REJECTED", f"Unbekannter Slack-Nutzer {user_id!r}.")
    actions = payload.get("actions") or []
    if not actions:
        return _finish(event, "PROCESSED")
    action = actions[0]
    finding = Finding.objects.filter(id=str(action.get("value", "")).strip() or 0).first() if str(action.get("value", "")).isdigit() else None
    if action.get("action_id") in ("ack", "reopen") and finding is None:
        return _finish(event, "REJECTED", "Finding nicht gefunden.")
    try:
        if action.get("action_id") == "ack":
            acknowledge(finding, member, source="SLACK", now=now)
        elif action.get("action_id") == "reopen":
            reopen(finding, member, source="SLACK", note=f"Per Slack von {member.name} wieder geöffnet.", now=now)
    except (InvalidTransition, ValidationError) as exc:
        return _finish(event, "REJECTED", str(exc))
    _finish(event, "PROCESSED")


def refresh_ci_status(finding: Finding, github) -> None:
    """Mirror the combined check-run status of the finding's PR branch (shown in the detail panel)."""
    if not finding.pr_number or not finding.pr_head_ref or finding.repository is None:
        return
    try:
        status = github.combined_ci_status(finding.repository.full_name, finding.pr_head_ref)
    except Exception as exc:  # noqa: BLE001 - CI status is informational; keep the last known value
        logger.warning("CI status of %s@%s failed: %s", finding.repository.full_name, finding.pr_head_ref, exc)
        return
    if status != finding.ci_status:
        finding.ci_status = status
        finding.save(update_fields=["ci_status", "updated_at"])


def _apply_pull_state(finding: Finding, github, now: datetime) -> bool:
    details = github.get_pull(finding.repository.full_name, finding.pr_number)
    if not details.get("merged"):
        if details.get("state") == "open":
            refresh_ci_status(finding, github)
        return False
    merged_at = parse_datetime(str(details.get("merged_at") or "")) or now
    mark_pr_merged(finding, merge_commit_sha=str(details.get("merge_commit_sha") or ""), merged_at=merged_at,
                   source="GITHUB", now=now)
    return True


def _process_github(event: WebhookEvent, github, now: datetime) -> None:
    payload = event.payload or {}
    if event.event_type != "pull_request" or payload.get("action") != "closed":
        return _finish(event, "PROCESSED")
    repo = str((payload.get("repository") or {}).get("full_name", ""))
    number = (payload.get("pull_request") or {}).get("number")
    for finding in Finding.objects.filter(repository__full_name=repo, pr_number=number,
                                          state__in=("NEW", "IN_PROGRESS")).select_related("repository"):
        _apply_pull_state(finding, github, now)  # the API, not the payload, decides
    _finish(event, "PROCESSED")


def process_webhook_event(event: WebhookEvent, *, github, slack, now: datetime | None = None) -> None:
    now = now or timezone.now()
    try:
        if event.source == "SLACK":
            _process_slack(event, now)
        elif event.source == "GITHUB":
            _process_github(event, github, now)
        else:
            _finish(event, "REJECTED", f"Unbekannte Quelle {event.source}.")
    except Exception as exc:  # noqa: BLE001 - keep the queue moving; the error is stored on the event
        logger.exception("Webhook event %s failed", event.id)
        _finish(event, "FAILED", str(exc))


def process_pending_webhooks(*, github, slack, now: datetime | None = None) -> int:
    count = 0
    for event in WebhookEvent.objects.filter(status="PENDING").order_by("received_at", "id"):
        process_webhook_event(event, github=github, slack=slack, now=now)
        count += 1
    return count


def reconcile_open_prs(*, github, now: datetime | None = None) -> int:
    """Hourly fallback for missed webhook deliveries."""
    now = now or timezone.now()
    merged = 0
    for finding in Finding.objects.filter(state__in=("NEW", "IN_PROGRESS"), pr_number__isnull=False,
                                          repository__isnull=False).select_related("repository"):
        try:
            if _apply_pull_state(finding, github, now):
                merged += 1
        except Exception:  # noqa: BLE001 - one broken PR lookup must not stop the hourly reconciliation
            logger.exception("Reconciling PR #%s of finding %s failed", finding.pr_number, finding.id)
    return merged
