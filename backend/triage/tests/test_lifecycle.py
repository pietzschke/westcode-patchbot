from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from inventory.notion_sync import set_monitoring
from triage.lifecycle import (
    InvalidTransition,
    acknowledge,
    extend_deadline,
    mark_fix_detected_on_branch,
    mark_pr_merged,
)
from triage.models import FindingEvent
from testing.factories import make_finding, make_member

BER = ZoneInfo("Europe/Berlin")
NOW = datetime(2026, 11, 6, 7, 0, tzinfo=BER)  # Friday


@pytest.mark.django_db
def test_acknowledge_sets_in_progress_and_working_day_deadline():
    owner = make_member(email="owner@westcode.de")
    f = make_finding(state="NEW", complexity="SIMPLE", assignee=owner)
    acknowledge(f, owner, source="WEB", now=NOW)
    f.refresh_from_db()
    assert f.state == "IN_PROGRESS"
    assert f.acknowledged_at == NOW
    assert f.deadline_at == datetime(2026, 11, 10, 7, 0, tzinfo=BER)
    assert FindingEvent.objects.filter(finding=f, actor=owner, from_state="NEW", to_state="IN_PROGRESS").exists()


@pytest.mark.django_db
def test_acknowledge_by_other_member_reassigns_and_logs():
    owner = make_member(email="owner@westcode.de")
    other = make_member(email="other@westcode.de")
    f = make_finding(state="NEW", assignee=owner)
    acknowledge(f, other, source="SLACK", now=NOW)
    assert f.assignee == other
    assert FindingEvent.objects.filter(finding=f, source="SLACK", note__icontains="übernommen").exists()


@pytest.mark.django_db
def test_takeover_while_in_progress_keeps_deadline():
    owner = make_member(email="owner@westcode.de")
    other = make_member(email="other@westcode.de")
    f = make_finding(state="IN_PROGRESS", assignee=owner, deadline_at=NOW + timedelta(days=2))
    acknowledge(f, other, source="WEB", now=NOW)
    assert (f.state, f.assignee, f.deadline_at) == ("IN_PROGRESS", other, NOW + timedelta(days=2))


@pytest.mark.django_db
def test_inactive_member_cannot_acknowledge():
    gone = make_member(email="gone@westcode.de", is_active=False)
    with pytest.raises(InvalidTransition):
        acknowledge(make_finding(state="NEW"), gone, source="WEB", now=NOW)


@pytest.mark.django_db
def test_merge_before_acknowledge_moves_to_waiting_live():
    f = make_finding(state="NEW")
    mark_pr_merged(f, merge_commit_sha="m1", merged_at=NOW, source="GITHUB", now=NOW)
    assert f.state == "PR_MERGED_WAITING_LIVE"
    assert (f.merge_commit_sha, f.pr_merged_at) == ("m1", NOW)
    assert f.deadline_at == datetime(2026, 11, 9, 7, 0, tzinfo=BER)
    assert f.events.filter(note__icontains="implizit").exists()


@pytest.mark.django_db
def test_merge_is_idempotent():
    f = make_finding(state="IN_PROGRESS")
    mark_pr_merged(f, merge_commit_sha="m1", merged_at=NOW, source="GITHUB", now=NOW)
    events = f.events.count()
    mark_pr_merged(f, merge_commit_sha="m1", merged_at=NOW, source="GITHUB", now=NOW + timedelta(hours=1))
    assert f.events.count() == events


@pytest.mark.django_db
def test_merge_for_non_deployed_repo_resolves():
    f = make_finding(state="IN_PROGRESS", repository__deployment_mode="NONE")
    mark_pr_merged(f, merge_commit_sha="m1", merged_at=NOW, source="GITHUB", now=NOW)
    assert f.state == "RESOLVED_NO_DEPLOYMENT"


@pytest.mark.django_db
def test_fix_detected_on_branch_uses_scanned_commit():
    f = make_finding(state="IN_PROGRESS")
    mark_fix_detected_on_branch(f, commit_sha="c0ffee", now=NOW)
    assert (f.state, f.merge_commit_sha) == ("PR_MERGED_WAITING_LIVE", "c0ffee")
    assert f.events.filter(note__icontains="ohne Patchbot-PR").exists()


@pytest.mark.django_db
def test_extend_only_once_per_stage_with_reason():
    owner = make_member(email="owner@westcode.de")
    f = make_finding(state="IN_PROGRESS", complexity="SIMPLE", assignee=owner, deadline_at=NOW)
    with pytest.raises(ValueError):
        extend_deadline(f, owner, reason="zu kurz", now=NOW)
    extend_deadline(f, owner, reason="Warten auf Upstream-Release 2.4.1", now=NOW)
    assert f.deadline_at == NOW + timedelta(days=4)  # 2 working days from Friday 07:00 → Tuesday 07:00
    with pytest.raises(InvalidTransition):
        extend_deadline(f, owner, reason="Noch eine Verlängerung bitte", now=NOW)


@pytest.mark.django_db
def test_invalid_transition_raises():
    owner = make_member(email="owner@westcode.de")
    with pytest.raises(InvalidTransition):
        acknowledge(make_finding(state="VERIFIED_LIVE"), owner, source="WEB", now=NOW)


@pytest.mark.django_db
def test_monitoring_off_suppresses_and_on_reopens():
    f = make_finding(state="IN_PROGRESS")
    set_monitoring(f.project, False, source="WEB")
    f.refresh_from_db()
    assert f.state == "SUPPRESSED_UNMONITORED"
    set_monitoring(f.project, True, source="WEB")
    f.refresh_from_db()
    assert f.state == "NEW"
    assert f.acknowledged_at is None
