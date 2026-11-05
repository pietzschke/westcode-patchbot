from datetime import datetime
from zoneinfo import ZoneInfo

from triage.schedule import due_jobs

BER = ZoneInfo("Europe/Berlin")


def at(*args):
    return datetime(*args, tzinfo=BER)


def test_daily_scan_due_once_after_0700():
    assert "daily_scan" not in due_jobs(at(2026, 11, 9, 6, 59), {})
    assert "daily_scan" in due_jobs(at(2026, 11, 9, 7, 0), {})
    last = {"daily_scan": at(2026, 11, 9, 7, 0)}
    assert "daily_scan" not in due_jobs(at(2026, 11, 9, 15, 0), last)
    assert "daily_scan" in due_jobs(at(2026, 11, 10, 7, 1), last)


def test_daily_jobs_run_in_order_before_the_scan():
    due = due_jobs(at(2026, 11, 9, 7, 0), {})
    assert due.index("signals_refresh") < due.index("notion_sync") < due.index("daily_scan")


def test_grace_eval_every_15_minutes():
    last = {"grace_eval": at(2026, 11, 9, 9, 0)}
    assert "grace_eval" not in due_jobs(at(2026, 11, 9, 9, 14), last)
    assert "grace_eval" in due_jobs(at(2026, 11, 9, 9, 15), last)


def test_pr_reconcile_hourly():
    last = {"pr_reconcile": at(2026, 11, 9, 9, 0)}
    assert "pr_reconcile" not in due_jobs(at(2026, 11, 9, 9, 59), last)
    assert "pr_reconcile" in due_jobs(at(2026, 11, 9, 10, 0), last)
