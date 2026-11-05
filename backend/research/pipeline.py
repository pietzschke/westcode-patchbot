"""Daily scan pipeline (spec v2.1 §3.3, §5, §6).

Order: repositories → asset links/suggestions → collect & upsert → exploit
signals → Claude triage → ownership → PRs → maintenance list → live
verification → Slack DMs. Any unexpected error marks the run FAILED (→ GREY).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Callable

from django.utils import timezone

from inventory.matching import link_containers_to_repositories, suggest_projects, sync_repositories
from research.collect import collect_and_upsert
from research.maintenance import sync_maintenance_updates
from research.models import ImageScanCache, ScanRun
from research.pr_engine import ensure_pr
from research.scan_runs import finalize_scan_run, start_scan_run
from research.signals_feed import apply_signals
from research.triage_ai import apply_triage
from triage.findings import log_event
from triage.models import OPEN_STATES
from triage.notifications import record_health, send_new_finding_dms
from triage.ownership import assign
from triage.verification import verify_findings

logger = logging.getLogger(__name__)


def lookup_image_scan(digest_ref: str) -> dict | None:
    cached = ImageScanCache.objects.filter(image_ref=digest_ref).first()
    return {"status": cached.status, "vulnerabilities": cached.vulnerabilities} if cached else None


def run_scan(
    *,
    github,
    trivy,
    llm,
    slack,
    bumper,
    worktrees,
    patcher=None,
    trigger: str = "SCHEDULED",
    release_checkout: Callable | None = None,
    now: datetime | None = None,
) -> ScanRun:
    now = now or timezone.now()
    run = start_scan_run(trigger, now=now)
    result = None
    try:
        sync_repositories(github)
        link_containers_to_repositories()
        suggest_projects()
        result = collect_and_upsert(run, github=github, trivy=trivy, now=now)

        for finding in result.findings:
            apply_signals(finding)
        for finding in result.findings:
            if finding.triage_status == "UNTRIAGED" or finding.state == "FILTERED_IRRELEVANT":
                checkout = result.checkouts.get(finding.repository.full_name) if finding.repository else None
                apply_triage(finding, client=llm, checkout=checkout.path if checkout else None, now=now)
        for finding in result.findings:
            if finding.state in OPEN_STATES:
                assign(finding, github=github, now=now)
        for finding in result.findings:
            if finding.state not in ("NEW", "IN_PROGRESS") or finding.layer != "APPLICATION":
                continue
            try:
                ensure_pr(finding, github=github, bumper=bumper, worktrees=worktrees, patcher=patcher, now=now)
            except Exception as exc:  # noqa: BLE001 - one failing PR must not stop the run
                logger.exception("PR handling failed for finding %s", finding.id)
                record_health("github", False, str(exc), now)
                log_event(finding, source="SYSTEM", from_state=finding.state, to_state=finding.state, at=now,
                          note=f"PR-Vorbereitung fehlgeschlagen: {exc}")

        sync_maintenance_updates(github=github)
        verify_findings(github=github, image_scan_lookup=lookup_image_scan, now=now)
        send_new_finding_dms(slack=slack, now=now)
    except Exception as exc:  # noqa: BLE001 - a crashed run must show up as FAILED, never as clean
        logger.exception("Scan run %s failed", run.id)
        return finalize_scan_run(run, now=timezone.now(), error=f"{type(exc).__name__}: {exc}")
    finally:
        if result is not None and release_checkout is not None:
            for checkout in result.checkouts.values():
                release_checkout(checkout)
    return finalize_scan_run(run, now=timezone.now())
