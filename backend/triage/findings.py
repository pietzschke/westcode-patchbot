"""Deduplicating upsert of scan candidates into findings (spec v2.1 §5.3)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from django.db import transaction
from django.utils import timezone

from triage.candidates import Candidate
from triage.clock import deadline_for
from triage.models import OPEN_STATES, PARKED_STATES, SEVERITY_RANK, TERMINAL_STATES, Finding, FindingEvent
from triage.versions import compare_versions, max_version


@dataclass
class UpsertResult:
    finding: Finding
    created: bool = False
    target_version_raised: bool = False
    muted: bool = False


def log_event(finding: Finding, *, actor=None, source: str, from_state: str, to_state: str, note: str = "", at=None):
    return FindingEvent.objects.create(
        finding=finding,
        at=at or timezone.now(),
        actor=actor,
        source=source,
        from_state=from_state,
        to_state=to_state,
        note=note,
    )


def _max_severity(*severities: str) -> str:
    return max((s or "UNKNOWN" for s in severities), key=lambda s: SEVERITY_RANK.get(s, 0))


def _merge_into(finding: Finding, candidate: Candidate, cve_ids: list[str], severity: str, target: str) -> bool:
    """Merge a rescan into an existing finding; returns True if the target version was raised."""
    old_target = finding.target_version
    finding.vulnerability_ids = sorted(set(finding.vulnerability_ids) | set(cve_ids))
    finding.highest_severity = _max_severity(finding.highest_severity, severity)
    finding.target_version = max_version(candidate.ecosystem, [old_target, target])
    finding.current_version = candidate.current_version or finding.current_version
    finding.save()
    return bool(old_target) and compare_versions(candidate.ecosystem, finding.target_version, old_target) > 0


def _start_new(finding: Finding, now: datetime) -> None:
    finding.state = "NEW"
    finding.discovered_at = now
    finding.acknowledged_at = None
    finding.extended_in_stage = ""
    finding.escalated_stage = 0
    finding.deadline_at = deadline_for(
        stage="NEW",
        complexity=finding.complexity,
        severity=finding.highest_severity,
        kev_listed=finding.kev_listed,
        start=now,
    )


def clear_dismissal(finding: Finding) -> None:
    finding.dismissal_mode = ""
    finding.dismissal_reason = ""
    finding.dismissed_by = None
    finding.dismissed_at = None
    finding.dismissed_severity = ""
    finding.dismissed_kev_listed = False
    finding.snoozed_until = None


def reopen_state(finding: Finding, now: datetime) -> str:
    """Re-enter the active lifecycle: a new NEW cycle, or SUPPRESSED_UNMONITORED while the project is not
    monitored (it becomes NEW once monitoring is re-enabled). Returns the new state; the caller saves."""
    if not finding.project.is_monitored:
        finding.state = "SUPPRESSED_UNMONITORED"
        return finding.state
    _start_new(finding, now)
    return finding.state


@transaction.atomic
def upsert_finding(candidate: Candidate, *, now: datetime | None = None) -> UpsertResult:
    now = now or timezone.now()
    cve_ids = sorted({v.id for v in candidate.vulns})
    severity = _max_severity(*(v.severity for v in candidate.vulns)) if candidate.vulns else "UNKNOWN"
    target = max_version(candidate.ecosystem, [v.fixed_version for v in candidate.vulns])
    same_key = Finding.objects.select_for_update().filter(
        project=candidate.project,
        layer=candidate.layer,
        target_ref=candidate.target_ref,
        ecosystem=candidate.ecosystem,
        package_name=candidate.package_name,
    )

    open_finding = same_key.filter(state__in=OPEN_STATES).first()
    if open_finding is not None:
        raised = _merge_into(open_finding, candidate, cve_ids, severity, target)
        if raised:
            log_event(open_finding, source="SYSTEM", from_state=open_finding.state, to_state=open_finding.state,
                      note=f"Zielversion auf {open_finding.target_version} angehoben (neue CVE).", at=now)
        return UpsertResult(open_finding, target_version_raised=raised)

    parked = same_key.filter(state__in=PARKED_STATES).order_by("-id").first()
    if parked is not None:
        known = set(parked.vulnerability_ids)
        _merge_into(parked, candidate, cve_ids, severity, target)
        if parked.state == "DISMISSED" and not set(cve_ids) <= known:
            previous = parked.state
            clear_dismissal(parked)
            reopen_state(parked, now)
            parked.save()
            log_event(parked, source="SYSTEM", from_state=previous, to_state=parked.state,
                      note="Neue CVE für ein als „nicht betroffen“ markiertes Paket.", at=now)
            return UpsertResult(parked)
        if parked.state == "FILTERED_IRRELEVANT":
            # Not muted: the pipeline re-evaluates filtered findings against fresh signals (spec §5.4).
            return UpsertResult(parked)
        return UpsertResult(parked, muted=True)

    previous = same_key.filter(state__in=TERMINAL_STATES).order_by("-id").first()
    finding = Finding(
        project=candidate.project,
        layer=candidate.layer,
        target_ref=candidate.target_ref,
        repository=candidate.repository,
        host=candidate.host,
        image_ref=candidate.image_ref,
        ecosystem=candidate.ecosystem,
        package_name=candidate.package_name,
        current_version=candidate.current_version,
        target_version=target,
        vulnerability_ids=cve_ids,
        highest_severity=severity,
        regression_of=previous,
        triage_status="UNTRIAGED",
        complexity="COMPLEX",
    )
    _start_new(finding, now)
    finding.save()
    log_event(finding, source="SYSTEM", from_state="", to_state="NEW",
              note="Regression nach Live-Verifikation." if previous else "Neu entdeckt.", at=now)
    return UpsertResult(finding, created=True)
