"""Worker schedule (spec v2.1 §3.3). Daily jobs run once per local day after their time, in order."""

from __future__ import annotations

from datetime import datetime, time, timedelta

from triage.clock import tz

SCHEDULE: list[tuple[str, str, object]] = [
    ("signals_refresh", "daily", time(6, 30)),
    ("notion_sync", "daily", time(6, 45)),
    ("slack_user_sync", "daily", time(6, 50)),
    ("daily_scan", "daily", time(7, 0)),
    ("grace_eval", "interval", timedelta(minutes=15)),
    ("pr_reconcile", "interval", timedelta(minutes=60)),
]


def due_jobs(now: datetime, last_runs: dict[str, datetime]) -> list[str]:
    local = now.astimezone(tz())
    due: list[str] = []
    for kind, mode, when in SCHEDULE:
        last = last_runs.get(kind)
        if mode == "daily":
            if local.time() >= when and (last is None or last.astimezone(tz()).date() < local.date()):
                due.append(kind)
        elif last is None or now - last >= when:
            due.append(kind)
    return due
