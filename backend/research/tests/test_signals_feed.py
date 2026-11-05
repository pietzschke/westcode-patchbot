from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from research.models import ExploitSignal
from research.signals_feed import apply_signals, refresh_epss, refresh_kev
from testing.factories import make_finding

BER = ZoneInfo("Europe/Berlin")


@pytest.mark.django_db
def test_refresh_kev_marks_listed_cves_and_unlists_removed_ones():
    ExploitSignal.objects.create(cve_id="CVE-2020-9999", kev_listed=True)
    feed = {"vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-10-01"}]}
    assert refresh_kev(fetch=lambda: feed) == 1
    listed = ExploitSignal.objects.get(cve_id="CVE-2026-0001")
    assert listed.kev_listed is True
    assert str(listed.kev_added_at) == "2026-10-01"
    assert ExploitSignal.objects.get(cve_id="CVE-2020-9999").kev_listed is False


@pytest.mark.django_db
def test_refresh_kev_failure_keeps_previous_state():
    ExploitSignal.objects.create(cve_id="CVE-2026-0001", kev_listed=True)

    def broken():
        raise ConnectionError("feed down")

    with pytest.raises(ConnectionError):
        refresh_kev(fetch=broken)
    assert ExploitSignal.objects.get(cve_id="CVE-2026-0001").kev_listed is True


@pytest.mark.django_db
def test_empty_kev_feed_is_rejected():
    ExploitSignal.objects.create(cve_id="CVE-2026-0001", kev_listed=True)
    with pytest.raises(ValueError):
        refresh_kev(fetch=lambda: {"vulnerabilities": []})
    assert ExploitSignal.objects.get(cve_id="CVE-2026-0001").kev_listed is True


@pytest.mark.django_db
def test_refresh_epss_batches_requests():
    calls = []

    def fetch(batch):
        calls.append(batch)
        return {"data": [{"cve": c, "epss": "0.12"} for c in batch]}

    ids = [f"CVE-2026-{i:04d}" for i in range(250)]
    assert refresh_epss(ids, fetch=fetch) == 250
    assert [len(c) for c in calls] == [100, 100, 50]
    assert ExploitSignal.objects.get(cve_id="CVE-2026-0000").epss == pytest.approx(0.12)


@pytest.mark.django_db
def test_apply_signals_sets_kev_and_max_epss():
    ExploitSignal.objects.create(cve_id="CVE-2026-0001", kev_listed=False, epss=0.02)
    ExploitSignal.objects.create(cve_id="CVE-2026-0002", kev_listed=True, epss=0.4)
    f = make_finding(vulnerability_ids=["CVE-2026-0001", "CVE-2026-0002"], kev_listed=False, max_epss=0.0)
    assert apply_signals(f) is True
    f.refresh_from_db()
    assert (f.kev_listed, f.max_epss) == (True, pytest.approx(0.4))
    assert apply_signals(f) is False


@pytest.mark.django_db
def test_kev_critical_new_finding_switches_to_wall_clock_deadline():
    discovered = datetime(2026, 11, 6, 7, 0, tzinfo=BER)  # Friday
    ExploitSignal.objects.create(cve_id="CVE-2026-0001", kev_listed=True)
    f = make_finding(vulnerability_ids=["CVE-2026-0001"], highest_severity="CRITICAL", state="NEW",
                     discovered_at=discovered, deadline_at=datetime(2026, 11, 9, 7, 0, tzinfo=BER))
    apply_signals(f)
    f.refresh_from_db()
    assert f.deadline_at == discovered + timedelta(hours=24)
