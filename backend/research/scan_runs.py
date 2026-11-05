"""Scan health bookkeeping (spec v2.1 §5.1)."""

from __future__ import annotations

from django.utils import timezone

from research.models import ScanRun, TargetScan


def start_scan_run(trigger: str, *, now=None) -> ScanRun:
    return ScanRun.objects.create(trigger=trigger, status="RUNNING", started_at=now or timezone.now())


def record_target(run: ScanRun, target_type: str, target_ref: str, result, *, duration_ms: int = 0) -> TargetScan:
    return TargetScan.objects.create(
        scan_run=run,
        target_type=target_type,
        target_ref=target_ref,
        status=result.status,
        error=result.error,
        vulnerability_count=len(result.vulnerabilities),
        duration_ms=duration_ms,
    )


def finalize_scan_run(run: ScanRun, *, now=None, error: str = "") -> ScanRun:
    statuses = list(run.targets.values_list("status", flat=True))
    failed = sum(1 for s in statuses if s == "FAILED")
    if error or (statuses and failed == len(statuses)):
        run.status = "FAILED"
    elif failed:
        run.status = "PARTIAL"
    else:
        run.status = "OK"
    run.error = error
    run.finished_at = now or timezone.now()
    run.save(update_fields=["status", "error", "finished_at"])
    return run
