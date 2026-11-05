"""Worker: scheduler, webhook processing and job execution (spec v2.1 §3.3)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from inventory.models import TeamMember
from inventory.notion_sync import sync_notion_projects
from research.maintenance import request_analysis
from research.models import MaintenanceUpdate
from research.pipeline import lookup_image_scan, record_trivy_db_health, run_scan
from research.signals_feed import apply_signals, refresh_epss, refresh_kev
from research.triage_ai import lift_filter_if_blocked
from triage.dismissal import evaluate_reopen_rules
from triage.jobs import enqueue
from triage.models import OPEN_STATES, PARKED_STATES, Finding, Job, ScheduleState
from triage.notifications import escalate_overdue, record_health, send_new_finding_dms, sync_slack_user_ids
from triage.schedule import due_jobs
from triage.verification import verify_findings
from triage.webhooks import process_pending_webhooks, reconcile_open_prs

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
RETRY_DELAY = timedelta(minutes=5)
STALE_AFTER = timedelta(hours=2)


@dataclass
class Deps:
    github: object
    slack: object
    llm: object
    trivy: object
    bumper: object
    worktrees: object
    patcher: object = None
    release_checkout: Callable | None = None
    handlers: dict = field(default_factory=dict)


# --- handlers (job, deps, now) ---------------------------------------------------
def _daily_scan(job, d: Deps, now):
    run_scan(github=d.github, trivy=d.trivy, llm=d.llm, slack=d.slack, bumper=d.bumper, worktrees=d.worktrees,
             patcher=d.patcher, trigger=job.payload.get("trigger", "SCHEDULED"), release_checkout=d.release_checkout)


def _notion_sync(job, d: Deps, now):
    if not settings.NOTION_API_KEY:
        logger.warning("Notion sync skipped: NOTION_API_KEY is not configured.")
        return
    try:
        sync_notion_projects()
    except Exception as exc:
        record_health("notion", False, str(exc), now)
        raise
    record_health("notion", True, now=now)


def _signals_refresh(job, d: Deps, now):
    refresh_kev()
    # Parked findings need fresh signals too: a new KEV listing must be able to reopen a dismissal.
    tracked = Finding.objects.filter(state__in=OPEN_STATES + PARKED_STATES)
    cves = {c for ids in tracked.values_list("vulnerability_ids", flat=True) for c in ids}
    refresh_epss(cves)
    for finding in tracked:
        apply_signals(finding)
        lift_filter_if_blocked(finding, now=now)  # spec §5.4: filtered findings are re-evaluated on signal changes
    evaluate_reopen_rules(now=now)


def _grace_eval(job, d: Deps, now):
    if d.trivy is not None:
        record_trivy_db_health(d.trivy, now)  # clears/sets the Trivy-DB cause between daily scans
    verify_findings(github=d.github, image_scan_lookup=lookup_image_scan, now=now)
    evaluate_reopen_rules(now=now)
    send_new_finding_dms(slack=d.slack, now=now)
    escalate_overdue(slack=d.slack, now=now)


def _maintenance_analysis(job, d: Deps, now):
    if d.llm is None:
        raise RuntimeError("Claude ist nicht konfiguriert (ANTHROPIC_API_KEY fehlt).")
    request_analysis(MaintenanceUpdate.objects.get(id=job.payload["id"]), github=d.github, client=d.llm)


def _test_dm(job, d: Deps, now):
    member = TeamMember.objects.get(id=job.payload["member_id"])
    if not member.slack_user_id:
        raise RuntimeError(f"{member.name} hat keine Slack-ID.")
    d.slack.post_message(member.slack_user_id, "👋 Test-Nachricht vom Westcode Patchbot – die Verbindung funktioniert.")


DEFAULT_HANDLERS: dict[str, Callable] = {
    "daily_scan": _daily_scan,
    "notion_sync": _notion_sync,
    "signals_refresh": _signals_refresh,
    "slack_user_sync": lambda job, d, now: sync_slack_user_ids(slack=d.slack),
    "grace_eval": _grace_eval,
    "pr_reconcile": lambda job, d, now: reconcile_open_prs(github=d.github, now=now),
    "maintenance_analysis": _maintenance_analysis,
    "test_dm": _test_dm,
}


# --- queue mechanics -------------------------------------------------------------
def schedule_due_jobs(*, now: datetime | None = None) -> list[str]:
    now = now or timezone.now()
    last_runs = {s.kind: s.last_run_at for s in ScheduleState.objects.all()}
    enqueued = []
    for kind in due_jobs(now, last_runs):
        if enqueue(kind, {"trigger": "SCHEDULED"}, unique=True) is None:
            continue  # a run of this kind is still queued/running: stay due so the slot is not lost
        ScheduleState.objects.update_or_create(kind=kind, defaults={"last_run_at": now})
        enqueued.append(kind)
    return enqueued


def recover_stale_jobs(*, now: datetime | None = None) -> int:
    now = now or timezone.now()
    return Job.objects.filter(status="RUNNING", locked_at__lt=now - STALE_AFTER).update(status="QUEUED", locked_at=None)


def _claim(now: datetime) -> Job | None:
    with transaction.atomic():
        job = (
            Job.objects.select_for_update(skip_locked=True)
            .filter(status="QUEUED", run_after__lte=now)
            .order_by("run_after", "id")
            .first()
        )
        if job is None:
            return None
        job.status, job.locked_at, job.attempts = "RUNNING", now, job.attempts + 1
        job.save(update_fields=["status", "locked_at", "attempts"])
        return job


def process_jobs(deps: Deps, *, now: datetime | None = None, limit: int = 50) -> int:
    now = now or timezone.now()
    handlers = {**DEFAULT_HANDLERS, **deps.handlers}
    processed = 0
    while processed < limit:
        job = _claim(now)
        if job is None:
            break
        processed += 1
        handler = handlers.get(job.kind)
        try:
            if handler is None:
                raise RuntimeError(f"Kein Handler für Job-Typ {job.kind!r}.")
            handler(job, deps, now)
        except Exception as exc:  # noqa: BLE001 - recorded on the job, retried with backoff
            logger.exception("Job %s (%s) failed", job.id, job.kind)
            job.last_error = f"{type(exc).__name__}: {exc}"[:4000]
            if job.attempts >= MAX_ATTEMPTS:
                job.status, job.finished_at = "FAILED", timezone.now()
            else:
                job.status, job.run_after = "QUEUED", now + RETRY_DELAY * job.attempts
            job.locked_at = None
            job.save(update_fields=["status", "run_after", "last_error", "locked_at", "finished_at"])
            continue
        job.status, job.finished_at, job.locked_at = "DONE", timezone.now(), None
        job.save(update_fields=["status", "finished_at", "locked_at"])
    return processed


def tick(deps: Deps, *, now: datetime | None = None) -> None:
    now = now or timezone.now()
    recover_stale_jobs(now=now)
    schedule_due_jobs(now=now)
    process_pending_webhooks(github=deps.github, slack=deps.slack, now=now)
    process_jobs(deps, now=now)


def build_deps() -> Deps:
    """Production wiring from settings (GitHub App, repo cache, Trivy, Claude, Slack)."""
    from pathlib import Path

    from django.core.exceptions import ImproperlyConfigured

    key_path = settings.GITHUB_APP_PRIVATE_KEY_PATH
    if not key_path or not Path(key_path).is_file():
        raise ImproperlyConfigured(
            f"GITHUB_APP_PRIVATE_KEY_PATH muss auf den Private Key der GitHub App zeigen (aktuell: {key_path!r})."
        )

    from controlplane.clients import slack_client
    from inventory.github_app import GitHubApp, RestGitHubClient
    from research.bumper import Bumper
    from research.repo_cache import BranchWorktrees, RepoCache
    from research.sandbox import SandboxPatcher
    from research.triage_ai import make_claude_client
    from research.trivy import TrivyScanner

    app = GitHubApp(
        app_id=settings.GITHUB_APP_ID,
        installation_id=settings.GITHUB_APP_INSTALLATION_ID,
        private_key_pem=Path(key_path).read_bytes(),
    )
    cache = RepoCache(Path(settings.PATCHBOT_REPO_CACHE), token_provider=app.installation_token)
    github = RestGitHubClient(app=app, checkout_provider=cache.as_checkout_provider())
    llm = make_claude_client()
    return Deps(
        github=github,
        slack=slack_client(),
        llm=llm,
        trivy=TrivyScanner(),
        bumper=Bumper(),
        worktrees=BranchWorktrees(cache),
        patcher=SandboxPatcher(llm) if (llm is not None and settings.PATCHBOT_AI_PATCHING) else None,
        release_checkout=cache.release,
    )
