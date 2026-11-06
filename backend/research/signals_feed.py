"""Exploit signals: CISA Known Exploited Vulnerabilities (KEV) and FIRST EPSS."""

from __future__ import annotations

from datetime import date
from typing import Callable, Iterable

import requests
from django.db import transaction
from django.utils import timezone

from research.models import ExploitSignal
from triage.clock import uses_wall_clock
from triage.findings import tighten_to_wall_clock

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_kev() -> dict:
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()


def fetch_epss(cve_ids: list[str]) -> dict:
    resp = requests.get(EPSS_URL, params={"cve": ",".join(cve_ids)}, timeout=60)
    resp.raise_for_status()
    return resp.json()


@transaction.atomic
def refresh_kev(fetch: Callable[[], dict] = fetch_kev) -> int:
    feed = fetch()
    entries = {
        str(v.get("cveID") or "").strip(): v.get("dateAdded")
        for v in feed.get("vulnerabilities") or []
        if v.get("cveID")
    }
    if not entries:
        # An empty catalogue is a broken download, never "nothing is exploited".
        raise ValueError("CISA KEV feed contained no vulnerabilities; keeping previous state.")
    now = timezone.now()
    for cve_id, added in entries.items():
        ExploitSignal.objects.update_or_create(
            cve_id=cve_id,
            defaults={"kev_listed": True, "kev_added_at": date.fromisoformat(added) if added else None, "updated_at": now},
        )
    ExploitSignal.objects.filter(kev_listed=True).exclude(cve_id__in=entries.keys()).update(kev_listed=False, updated_at=now)
    return len(entries)


def refresh_epss(cve_ids: Iterable[str], fetch: Callable[[list[str]], dict] = fetch_epss, batch_size: int = 100) -> int:
    ids = sorted({c for c in cve_ids if c and c.startswith("CVE-")})
    updated = 0
    now = timezone.now()
    for start in range(0, len(ids), batch_size):
        batch = ids[start : start + batch_size]
        for row in fetch(batch).get("data") or []:
            try:
                score = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
            ExploitSignal.objects.update_or_create(cve_id=row["cve"], defaults={"epss": score, "updated_at": now})
            updated += 1
    return updated


def apply_signals(finding) -> bool:
    """Copy KEV/EPSS onto the finding; returns True when either changed."""
    signals = list(ExploitSignal.objects.filter(cve_id__in=finding.vulnerability_ids or []))
    kev = any(s.kev_listed for s in signals)
    epss = max((s.epss or 0.0 for s in signals), default=0.0)
    if kev == finding.kev_listed and abs(epss - finding.max_epss) < 1e-9:
        return False
    became_wall_clock = not uses_wall_clock(finding.highest_severity, finding.kev_listed) and uses_wall_clock(
        finding.highest_severity, kev
    )
    finding.kev_listed = kev
    finding.max_epss = epss
    if became_wall_clock:
        tighten_to_wall_clock(finding)  # every open stage, not only NEW (spec §6.2, D-2)
    finding.save()
    return True
