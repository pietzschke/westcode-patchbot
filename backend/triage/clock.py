"""Working-day deadline clock (spec v2.1 §6.2, decision D-2).

Deadlines count Mon–Fri working days in Europe/Berlin, skipping public
holidays (NRW by default). A start on a weekend/holiday counts from 08:00 of
the next working day. CRITICAL findings listed in CISA KEV use wall-clock time.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
from typing import Iterable
from zoneinfo import ZoneInfo

import holidays as holidays_lib
from django.conf import settings

WORKDAY_START = time(8, 0)
WORKDAY_END = time(18, 0)

WORKING_DAYS = {
    ("NEW", "SIMPLE"): 1,
    ("NEW", "COMPLEX"): 1,
    ("IN_PROGRESS", "SIMPLE"): 2,
    ("IN_PROGRESS", "COMPLEX"): 5,
    ("PR_MERGED_WAITING_LIVE", "SIMPLE"): 1,
    ("PR_MERGED_WAITING_LIVE", "COMPLEX"): 1,
}
WALL_CLOCK = {
    ("NEW", "SIMPLE"): timedelta(hours=24),
    ("NEW", "COMPLEX"): timedelta(hours=24),
    ("IN_PROGRESS", "SIMPLE"): timedelta(hours=48),
    ("IN_PROGRESS", "COMPLEX"): timedelta(days=7),
    ("PR_MERGED_WAITING_LIVE", "SIMPLE"): timedelta(hours=24),
    ("PR_MERGED_WAITING_LIVE", "COMPLEX"): timedelta(hours=24),
}


def tz() -> ZoneInfo:
    return ZoneInfo(getattr(settings, "PATCHBOT_TIMEZONE", "Europe/Berlin"))


def default_holidays(years: Iterable[int]) -> set[date]:
    subdivision = getattr(settings, "PATCHBOT_HOLIDAY_SUBDIVISION", "NW")
    days = set(holidays_lib.Germany(subdiv=subdivision, years=list(years)).keys())
    days.update(date.fromisoformat(d) for d in getattr(settings, "PATCHBOT_EXTRA_HOLIDAYS", []))
    return days


def holidays_around(moment: datetime) -> set[date]:
    year = moment.astimezone(tz()).year
    return default_holidays([year, year + 1])


def is_working_day(day: date, holidays: set[date]) -> bool:
    return day.weekday() < 5 and day not in holidays


def _next_working_day(day: date, holidays: set[date]) -> date:
    day += timedelta(days=1)
    while not is_working_day(day, holidays):
        day += timedelta(days=1)
    return day


def add_working_days(start: datetime, days: int, holidays: set[date]) -> datetime:
    local = start.astimezone(tz())
    if not is_working_day(local.date(), holidays):
        local = datetime.combine(_next_working_day(local.date(), holidays), WORKDAY_START, tz())
    day = local.date()
    for _ in range(days):
        day = _next_working_day(day, holidays)
    return datetime.combine(day, local.time().replace(tzinfo=None), tz())


def uses_wall_clock(severity: str, kev_listed: bool) -> bool:
    return severity == "CRITICAL" and kev_listed


def deadline_for(
    *, stage: str, complexity: str, severity: str, kev_listed: bool, start: datetime, holidays: set[date] | None = None
) -> datetime:
    key = (stage, complexity if complexity in ("SIMPLE", "COMPLEX") else "COMPLEX")
    if uses_wall_clock(severity, kev_listed):
        return start + WALL_CLOCK[key]
    return add_working_days(start, WORKING_DAYS[key], holidays if holidays is not None else holidays_around(start))


def next_posting_time(now: datetime, holidays: set[date] | None = None) -> datetime:
    """Earliest moment at or after ``now`` inside the escalation window (working days 08:00–18:00)."""
    holidays = holidays if holidays is not None else holidays_around(now)
    local = now.astimezone(tz())
    if is_working_day(local.date(), holidays):
        if WORKDAY_START <= local.time() < WORKDAY_END:
            return now
        if local.time() < WORKDAY_START:
            return datetime.combine(local.date(), WORKDAY_START, tz())
    return datetime.combine(_next_working_day(local.date(), holidays), WORKDAY_START, tz())
