"""Status-Ampel (spec v2.1 §6.7). GREY whenever Patchbot cannot vouch for the data — never a false green."""

from __future__ import annotations

from datetime import datetime, timedelta

from django.db.models import Q
from django.utils import timezone

from fleet.models import Host
from research.models import MaintenanceUpdate, ScanRun
from triage.models import OPEN_STATES, Finding, IntegrationHealth

SCAN_MAX_AGE = timedelta(hours=26)
AGENT_MAX_SILENCE = timedelta(minutes=60)
LABELS = {
    "GREY": "Datenlage unvollständig",
    "RED": "Handlungsbedarf",
    "YELLOW": "In Bearbeitung",
    "GREEN": "Alles im grünen Bereich",
}


def _data_health_causes(now: datetime) -> list[dict]:
    causes: list[dict] = []
    last_success = (
        ScanRun.objects.filter(status__in=("OK", "PARTIAL"), finished_at__isnull=False).order_by("-finished_at").first()
    )
    if last_success is None:
        causes.append({"code": "no_successful_scan", "text": "Es gibt noch keinen erfolgreichen Scan."})
    elif now - last_success.finished_at > SCAN_MAX_AGE:
        hours = int((now - last_success.finished_at).total_seconds() // 3600)
        causes.append({"code": "no_successful_scan", "text": f"Letzter erfolgreicher Scan ist {hours} h alt."})

    latest = ScanRun.objects.filter(finished_at__isnull=False).order_by("-started_at", "-id").first()
    if latest is not None and latest.status == "FAILED":
        causes.append({"code": "scan_failed", "text": f"Letzter Scan fehlgeschlagen. {latest.error}".strip()})
    elif latest is not None and latest.status == "PARTIAL":
        failed = list(latest.targets.filter(status="FAILED").values_list("target_ref", flat=True))
        shown = ", ".join(r.split(":", 1)[-1] for r in failed[:3]) + (" …" if len(failed) > 3 else "")
        causes.append({"code": "scan_partial", "text": f"{len(failed)} Scan-Ziel(e) fehlgeschlagen: {shown}"})

    for host in Host.objects.filter(project__is_monitored=True).filter(
        Q(last_seen_at__isnull=True) | Q(last_seen_at__lt=now - AGENT_MAX_SILENCE)
    ):
        if host.last_seen_at is None:
            text = f"Agent auf {host.hostname} hat noch nie gemeldet."
        else:
            minutes = int((now - host.last_seen_at).total_seconds() // 60)
            text = f"Agent auf {host.hostname} seit {minutes} min stumm."
        causes.append({"code": "agent_stale", "text": text})

    for health in IntegrationHealth.objects.filter(ok=False):
        causes.append({"code": "integration_failing", "text": f"{health.name}: {health.last_error}".strip()})
    return causes


def compute_ampel(*, now: datetime | None = None) -> dict:
    now = now or timezone.now()
    open_findings = Finding.objects.filter(state__in=OPEN_STATES)
    counts = {
        "new": open_findings.filter(state="NEW").count(),
        "in_progress": open_findings.filter(state="IN_PROGRESS").count(),
        "waiting_live": open_findings.filter(state="PR_MERGED_WAITING_LIVE").count(),
        "overdue": open_findings.filter(deadline_at__lt=now).count(),
        "unassigned": open_findings.filter(assignee__isnull=True).count(),
        "filtered": Finding.objects.filter(state="FILTERED_IRRELEVANT").count(),
        "snoozed": Finding.objects.filter(state="SNOOZED").count(),
        "dismissed": Finding.objects.filter(state="DISMISSED").count(),
        "maintenance": MaintenanceUpdate.objects.count(),
    }
    if counts["new"] or counts["overdue"] or counts["unassigned"]:
        findings_color = "RED"
    elif open_findings.exists():
        findings_color = "YELLOW"
    else:
        findings_color = "GREEN"
    causes = _data_health_causes(now)
    color = "GREY" if causes else findings_color
    return {
        "color": color,
        "label_de": LABELS[color],
        "findings_color": findings_color,
        "causes": causes,
        "counts": counts,
        "computed_at": now.isoformat(),
    }
