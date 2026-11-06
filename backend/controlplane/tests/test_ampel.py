from datetime import datetime, timedelta, timezone

import pytest

from controlplane.ampel import compute_ampel
from research.models import ScanRun, TargetScan
from triage.models import IntegrationHealth
from testing.factories import make_finding, make_host, make_member, make_project

NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)


def codes(ampel):
    return {c["code"] for c in ampel["causes"]}


@pytest.fixture
def healthy(db):
    ScanRun.objects.create(status="OK", trigger="SCHEDULED", started_at=NOW - timedelta(hours=2),
                           finished_at=NOW - timedelta(hours=2))
    make_host(slug="mdb", project=make_project(slug="wuerth", is_monitored=True), last_seen_at=NOW - timedelta(minutes=10))


def test_grey_without_successful_scan(db):
    ampel = compute_ampel(now=NOW)
    assert ampel["color"] == "GREY"
    assert "no_successful_scan" in codes(ampel)


def test_grey_when_last_scan_too_old(healthy):
    ScanRun.objects.update(finished_at=NOW - timedelta(hours=27))
    assert compute_ampel(now=NOW)["color"] == "GREY"


def test_grey_when_latest_scan_partial(healthy):
    run = ScanRun.objects.create(status="PARTIAL", trigger="MANUAL", started_at=NOW - timedelta(minutes=30),
                                 finished_at=NOW - timedelta(minutes=20))
    TargetScan.objects.create(scan_run=run, target_type="REPO", target_ref="repo:westcoder/mdb", status="FAILED",
                              error="clone failed")
    ampel = compute_ampel(now=NOW)
    assert ampel["color"] == "GREY"
    assert "scan_partial" in codes(ampel)
    assert any("westcoder/mdb" in c["text"] for c in ampel["causes"])


def test_grey_when_agent_stale(healthy):
    make_host(slug="stale", project=make_project(slug="ses", is_monitored=True), last_seen_at=NOW - timedelta(minutes=61))
    make_host(slug="ignored", project=make_project(slug="old", is_monitored=False), last_seen_at=None)
    ampel = compute_ampel(now=NOW)
    assert ampel["color"] == "GREY"
    stale = [c for c in ampel["causes"] if c["code"] == "agent_stale"]
    assert len(stale) == 1 and "stale.westcode.de" in stale[0]["text"]


def test_grey_when_slack_failing(healthy):
    IntegrationHealth.objects.create(name="slack", ok=False, last_error="invalid_auth", checked_at=NOW)
    assert "integration_failing" in codes(compute_ampel(now=NOW))


def test_grey_still_reports_underlying_finding_color(db):
    make_finding(state="NEW")
    ampel = compute_ampel(now=NOW)
    assert (ampel["color"], ampel["findings_color"]) == ("GREY", "RED")


def test_red_for_new_finding(healthy):
    make_finding(state="NEW", assignee=make_member(email="a@westcode.de"), deadline_at=NOW + timedelta(hours=5))
    ampel = compute_ampel(now=NOW)
    assert ampel["color"] == "RED"
    assert ampel["label_de"] == "Handlungsbedarf"


def test_red_for_overdue(healthy):
    make_finding(state="IN_PROGRESS", assignee=make_member(email="a@westcode.de"), deadline_at=NOW - timedelta(minutes=1))
    assert compute_ampel(now=NOW)["color"] == "RED"


def test_red_for_unassigned(healthy):
    make_finding(state="IN_PROGRESS", assignee=None, deadline_at=NOW + timedelta(days=1))
    assert compute_ampel(now=NOW)["color"] == "RED"


def test_yellow_when_all_acknowledged_in_time(healthy):
    make_finding(state="IN_PROGRESS", assignee=make_member(email="a@westcode.de"), deadline_at=NOW + timedelta(days=1))
    ampel = compute_ampel(now=NOW)
    assert ampel["color"] == "YELLOW"
    assert ampel["counts"]["in_progress"] == 1


def test_green_when_nothing_open(healthy):
    make_finding(state="VERIFIED_LIVE")
    make_finding(state="FILTERED_IRRELEVANT")
    ampel = compute_ampel(now=NOW)
    assert ampel["color"] == "GREEN"
    assert ampel["counts"]["filtered"] == 1


def test_stale_agent_on_host_running_monitored_containers_turns_grey(healthy):
    from testing.factories import make_container

    host = make_host(slug="shared", project=None, last_seen_at=NOW - timedelta(hours=3))
    make_container(host, project=make_project(slug="ses", is_monitored=True))
    make_container(host, project=make_project(slug="ses2", is_monitored=True))
    ampel = compute_ampel(now=NOW)
    assert ampel["color"] == "GREY"
    assert [c["text"] for c in ampel["causes"] if c["code"] == "agent_stale"] == [
        "Agent auf shared.westcode.de seit 180 min stumm."]
