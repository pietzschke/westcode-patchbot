from datetime import date, datetime
from zoneinfo import ZoneInfo

from triage.clock import add_working_days, deadline_for, default_holidays, next_posting_time

BER = ZoneInfo("Europe/Berlin")
HOL = {date(2026, 12, 25), date(2026, 12, 26)}


def dt(*args):
    return datetime(*args, tzinfo=BER)


def test_friday_plus_one_working_day_is_monday_same_time():
    assert add_working_days(dt(2026, 11, 6, 7, 0), 1, HOL) == dt(2026, 11, 9, 7, 0)


def test_weekend_start_counts_from_next_working_day_0800():
    assert add_working_days(dt(2026, 11, 7, 10, 0), 1, HOL) == dt(2026, 11, 10, 8, 0)


def test_holidays_are_skipped():
    assert add_working_days(dt(2026, 12, 24, 9, 0), 1, HOL) == dt(2026, 12, 28, 9, 0)


def test_five_working_days_from_thursday():
    assert add_working_days(dt(2026, 11, 5, 10, 0), 5, HOL) == dt(2026, 11, 12, 10, 0)


def test_utc_input_is_interpreted_in_berlin_time():
    utc_friday_0600 = datetime(2026, 11, 6, 6, 0, tzinfo=ZoneInfo("UTC"))  # 07:00 Berlin
    assert add_working_days(utc_friday_0600, 1, HOL) == dt(2026, 11, 9, 7, 0)


def test_complex_in_progress_uses_five_working_days():
    start = dt(2026, 11, 6, 7, 0)
    assert deadline_for(stage="IN_PROGRESS", complexity="COMPLEX", severity="HIGH", kev_listed=False,
                        start=start, holidays=HOL) == dt(2026, 11, 13, 7, 0)


def test_kev_critical_uses_wall_clock_hours():
    start = dt(2026, 11, 6, 7, 0)
    assert deadline_for(stage="NEW", complexity="SIMPLE", severity="CRITICAL", kev_listed=True,
                        start=start, holidays=HOL) == dt(2026, 11, 7, 7, 0)
    assert deadline_for(stage="IN_PROGRESS", complexity="SIMPLE", severity="CRITICAL", kev_listed=True,
                        start=start, holidays=HOL) == dt(2026, 11, 8, 7, 0)
    assert deadline_for(stage="IN_PROGRESS", complexity="COMPLEX", severity="CRITICAL", kev_listed=True,
                        start=start, holidays=HOL) == dt(2026, 11, 13, 7, 0)
    assert deadline_for(stage="PR_MERGED_WAITING_LIVE", complexity="SIMPLE", severity="CRITICAL", kev_listed=True,
                        start=start, holidays=HOL) == dt(2026, 11, 7, 7, 0)


def test_critical_without_kev_uses_working_days():
    assert deadline_for(stage="NEW", complexity="SIMPLE", severity="CRITICAL", kev_listed=False,
                        start=dt(2026, 11, 6, 7, 0), holidays=HOL) == dt(2026, 11, 9, 7, 0)


def test_posting_window():
    assert next_posting_time(dt(2026, 11, 7, 10, 0), HOL) == dt(2026, 11, 9, 8, 0)    # Saturday
    assert next_posting_time(dt(2026, 11, 9, 19, 0), HOL) == dt(2026, 11, 10, 8, 0)   # Monday evening
    assert next_posting_time(dt(2026, 11, 9, 6, 0), HOL) == dt(2026, 11, 9, 8, 0)     # Monday early
    assert next_posting_time(dt(2026, 11, 9, 9, 30), HOL) == dt(2026, 11, 9, 9, 30)   # inside window
    assert next_posting_time(dt(2026, 12, 25, 10, 0), HOL) == dt(2026, 12, 28, 8, 0)  # holiday


def test_default_holidays_are_nrw_plus_extra(settings):
    settings.PATCHBOT_EXTRA_HOLIDAYS = ["2026-12-24"]
    hol = default_holidays([2026])
    assert date(2026, 11, 1) in hol      # Allerheiligen (NRW)
    assert date(2026, 12, 24) in hol     # configured extra day
    assert date(2026, 10, 31) not in hol  # Reformationstag is not a holiday in NRW
