from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from triage.models import IntegrationHealth, NotificationLog
from triage.notifications import escalate_overdue, send_new_finding_dms, sync_slack_user_ids
from testing.factories import make_finding, make_member
from testing.fakes import FakeSlack

BER = ZoneInfo("Europe/Berlin")
MONDAY_9 = datetime(2026, 11, 9, 9, 0, tzinfo=BER)
SATURDAY_10 = datetime(2026, 11, 7, 10, 0, tzinfo=BER)


@pytest.fixture
def team(db, settings):
    settings.SLACK_TEAM_CHANNEL_ID = "C-TEAM"
    return make_member(email="a@westcode.de", slack_user_id="UA"), make_member(email="b@westcode.de", slack_user_id="UB")


def test_one_aggregated_dm_per_assignee(team):
    a, b = team
    for _ in range(3):
        make_finding(state="NEW", assignee=a, triage_status="TRIAGED")
    make_finding(state="NEW", assignee=b, triage_status="TRIAGED")
    slack = FakeSlack()
    assert send_new_finding_dms(slack=slack, now=MONDAY_9) == 2
    dm_a = next(m for m in slack.messages if m[0] == "UA")
    assert sum(1 for blk in dm_a[2] if blk["type"] == "actions") == 3
    assert all(el["action_id"] == "ack" for blk in dm_a[2] if blk["type"] == "actions" for el in blk["elements"][:1])
    assert NotificationLog.objects.filter(kind="NEW_DM").count() == 4


def test_dms_are_not_resent(team):
    a, _ = team
    make_finding(state="NEW", assignee=a)
    slack = FakeSlack()
    send_new_finding_dms(slack=slack, now=MONDAY_9)
    send_new_finding_dms(slack=slack, now=MONDAY_9)
    assert len(slack.messages) == 1



def test_reopened_finding_is_dmed_again_once_per_new_cycle(team):
    from datetime import timedelta

    from triage.dismissal import dismiss, reopen

    a, _ = team
    f = make_finding(state="NEW", assignee=a, highest_severity="MEDIUM", discovered_at=MONDAY_9 - timedelta(hours=1))
    slack = FakeSlack()
    assert send_new_finding_dms(slack=slack, now=MONDAY_9) == 1

    later = MONDAY_9 + timedelta(days=2)
    dismiss(f, a, mode="SNOOZED", reason="Wartet auf Upstream-Release", snooze_days=14, source="WEB", slack=slack,
            now=MONDAY_9 + timedelta(hours=1))
    reopen(f, None, source="SYSTEM", note="Zurückstellung abgelaufen.", now=later)

    assert send_new_finding_dms(slack=slack, now=later) == 1
    assert send_new_finding_dms(slack=slack, now=later + timedelta(minutes=5)) == 0
    assert [m[0] for m in slack.messages] == ["UA", "UA"]
    assert NotificationLog.objects.filter(finding=f, kind="NEW_DM").count() == 2

def test_filtered_and_in_progress_findings_are_not_sent(team):
    a, _ = team
    make_finding(state="FILTERED_IRRELEVANT", assignee=a)
    make_finding(state="IN_PROGRESS", assignee=a)
    assert send_new_finding_dms(slack=FakeSlack(), now=MONDAY_9) == 0


def test_unassigned_goes_to_team_channel(team):
    make_finding(state="NEW", assignee=None, assigned_reason_de="Projekt hat keinen aktiven Owner in Notion")
    slack = FakeSlack()
    send_new_finding_dms(slack=slack, now=MONDAY_9)
    channel, text, _ = slack.messages[0]
    assert channel == "C-TEAM"
    assert "keinen aktiven Owner" in text


def test_escalation_posts_once_per_stage(team):
    a, _ = team
    f = make_finding(state="NEW", assignee=a, deadline_at=datetime(2026, 11, 9, 7, 0, tzinfo=BER))
    slack = FakeSlack()
    assert escalate_overdue(slack=slack, now=MONDAY_9) == 1
    assert escalate_overdue(slack=slack, now=MONDAY_9) == 0
    f.refresh_from_db()
    assert f.escalated_stage == 1
    assert slack.messages[0][0] == "C-TEAM"
    assert "<@UA>" in slack.messages[0][1]
    assert f.events.filter(note__icontains="Eskaliert").exists()


def test_next_stage_escalates_again(team):
    a, _ = team
    f = make_finding(state="IN_PROGRESS", assignee=a, escalated_stage=1,
                     deadline_at=datetime(2026, 11, 9, 7, 0, tzinfo=BER))
    assert escalate_overdue(slack=FakeSlack(), now=MONDAY_9) == 1
    f.refresh_from_db()
    assert f.escalated_stage == 2


def test_escalation_waits_for_posting_window(team):
    a, _ = team
    make_finding(state="NEW", assignee=a, deadline_at=datetime(2026, 11, 7, 7, 0, tzinfo=BER))
    assert escalate_overdue(slack=FakeSlack(), now=SATURDAY_10) == 0


def test_kev_critical_escalates_immediately(team):
    a, _ = team
    make_finding(state="NEW", assignee=a, highest_severity="CRITICAL", kev_listed=True,
                 deadline_at=datetime(2026, 11, 7, 7, 0, tzinfo=BER))
    assert escalate_overdue(slack=FakeSlack(), now=SATURDAY_10) == 1


def test_slack_failure_is_retried_and_recorded(team):
    a, _ = team
    make_finding(state="NEW", assignee=a)
    assert send_new_finding_dms(slack=FakeSlack(fail=True), now=MONDAY_9) == 0
    assert NotificationLog.objects.count() == 0
    health = IntegrationHealth.objects.get(name="slack")
    assert health.ok is False and "invalid_auth" in health.last_error
    assert send_new_finding_dms(slack=FakeSlack(), now=MONDAY_9) == 1
    assert IntegrationHealth.objects.get(name="slack").ok is True


def test_sync_slack_user_ids(db):
    member = make_member(email="new@westcode.de", slack_user_id=None)
    make_member(email="unknown@westcode.de", slack_user_id=None)
    assert sync_slack_user_ids(slack=FakeSlack(users={"new@westcode.de": "UNEW"})) == 1
    member.refresh_from_db()
    assert member.slack_user_id == "UNEW"


def _section_texts(blocks):
    return " ".join(b["text"]["text"] for b in blocks if b["type"] == "section")


def _action_ids(blocks):
    return [el["action_id"] for b in blocks if b["type"] == "actions" for el in b["elements"]]


def test_escalation_blocks_carry_header_and_mention(team):
    a, _ = team
    make_finding(state="NEW", assignee=a, deadline_at=datetime(2026, 11, 9, 7, 0, tzinfo=BER))
    slack = FakeSlack()
    escalate_overdue(slack=slack, now=MONDAY_9)
    rendered = _section_texts(slack.messages[0][2])
    assert "Eskalation (nicht bestätigt)" in rendered
    assert "<@UA>" in rendered
    assert "ack" in _action_ids(slack.messages[0][2])


def test_escalation_after_merge_has_no_ack_button(team):
    a, _ = team
    make_finding(state="PR_MERGED_WAITING_LIVE", assignee=a, escalated_stage=2,
                 deadline_at=datetime(2026, 11, 9, 7, 0, tzinfo=BER))
    slack = FakeSlack()
    assert escalate_overdue(slack=slack, now=MONDAY_9) == 1
    assert "ack" not in _action_ids(slack.messages[0][2])
    assert "nach Merge noch nicht live" in _section_texts(slack.messages[0][2])


def test_target_raised_dm_goes_once_to_in_progress_assignee_in_aggregated_dm(team):
    a, _ = team
    make_finding(state="NEW", assignee=a)
    raised = make_finding(state="IN_PROGRESS", assignee=a, target_version="4.17.21")
    slack = FakeSlack()
    assert send_new_finding_dms(slack=slack, now=MONDAY_9, target_raised=[raised]) == 1
    assert len(slack.messages) == 1  # one aggregated DM per person and run
    channel, _, blocks = slack.messages[0]
    assert channel == "UA"
    assert "Zielversion angehoben" in _section_texts(blocks)
    assert NotificationLog.objects.filter(finding=raised, kind="TARGET_RAISED").count() == 1

    assert send_new_finding_dms(slack=slack, now=MONDAY_9, target_raised=[raised]) == 0
    raised.target_version = "4.17.22"
    raised.save()
    assert send_new_finding_dms(slack=slack, now=MONDAY_9, target_raised=[raised]) == 1


def test_target_raised_dm_skips_findings_that_are_no_longer_in_progress(team):
    a, _ = team
    f = make_finding(state="PR_MERGED_WAITING_LIVE", assignee=a)
    assert send_new_finding_dms(slack=FakeSlack(), now=MONDAY_9, target_raised=[f]) == 0
