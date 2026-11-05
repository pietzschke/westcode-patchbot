from datetime import datetime, timedelta, timezone

import pytest
from django.core.exceptions import ValidationError

from triage.dismissal import dismiss, evaluate_reopen_rules, reopen
from testing.factories import make_finding, make_member
from testing.fakes import FakeSlack

NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)
REASON = "Nur im Build-Container genutzt, nicht im Runtime-Image."


@pytest.fixture
def actor(db, settings):
    settings.SLACK_TEAM_CHANNEL_ID = "C-TEAM"
    return make_member(email="dev@westcode.de", name="Dev", slack_user_id="U3")


def test_reason_is_mandatory(actor):
    with pytest.raises(ValidationError):
        dismiss(make_finding(), actor, mode="DISMISSED", reason="passt", source="WEB", slack=FakeSlack(), now=NOW)


def test_mode_and_snooze_days_are_validated(actor):
    with pytest.raises(ValidationError):
        dismiss(make_finding(), actor, mode="IGNORED", reason=REASON, source="WEB", slack=FakeSlack(), now=NOW)
    with pytest.raises(ValidationError):
        dismiss(make_finding(), actor, mode="SNOOZED", reason=REASON, snooze_days=365, source="WEB",
                slack=FakeSlack(), now=NOW)


@pytest.mark.parametrize("severity,posts", [("CRITICAL", 1), ("HIGH", 1), ("MEDIUM", 0)])
def test_transparency_post_for_high_and_critical(actor, severity, posts):
    slack = FakeSlack()
    f = make_finding(highest_severity=severity)
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=slack, now=NOW)
    assert (f.state, f.dismissed_by, f.dismissal_reason) == ("DISMISSED", actor, REASON)
    assert f.events.filter(actor=actor, to_state="DISMISSED").exists()
    assert len(slack.messages) == posts
    if posts:
        channel, text, blocks = slack.messages[0]
        assert channel == "C-TEAM"
        assert REASON in text and "<@U3>" in text
        assert any(el.get("action_id") == "reopen" for b in blocks for el in b.get("elements", []))


def test_slack_failure_does_not_block_dismissal(actor):
    f = make_finding(highest_severity="CRITICAL")
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=FakeSlack(fail=True), now=NOW)
    assert f.state == "DISMISSED"
    assert f.events.filter(note__icontains="Transparenz").exists()


def test_snooze_sets_until_and_reopens_on_expiry(actor):
    f = make_finding(highest_severity="MEDIUM")
    dismiss(f, actor, mode="SNOOZED", reason=REASON, snooze_days=14, source="WEB", slack=FakeSlack(), now=NOW)
    assert f.snoozed_until == NOW + timedelta(days=14)
    assert evaluate_reopen_rules(now=NOW + timedelta(days=13)) == []
    reopened = evaluate_reopen_rules(now=NOW + timedelta(days=14, minutes=1))
    f.refresh_from_db()
    assert reopened == [f]
    assert (f.state, f.snoozed_until) == ("NEW", None)


@pytest.mark.parametrize("change", [{"highest_severity": "CRITICAL"}, {"kev_listed": True}])
def test_dismissed_reopens_when_risk_rises(actor, change):
    f = make_finding(highest_severity="HIGH", kev_listed=False)
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=FakeSlack(), now=NOW)
    for key, value in change.items():
        setattr(f, key, value)
    f.save()
    evaluate_reopen_rules(now=NOW)
    f.refresh_from_db()
    assert f.state == "NEW"
    assert f.events.filter(from_state="DISMISSED", to_state="NEW").exists()


def test_dismissed_stays_when_risk_unchanged(actor):
    f = make_finding(highest_severity="HIGH")
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=FakeSlack(), now=NOW)
    evaluate_reopen_rules(now=NOW + timedelta(days=30))
    f.refresh_from_db()
    assert f.state == "DISMISSED"


def test_dismissed_reopens_after_180_days(actor):
    f = make_finding(highest_severity="MEDIUM")
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=FakeSlack(), now=NOW)
    evaluate_reopen_rules(now=NOW + timedelta(days=181))
    f.refresh_from_db()
    assert f.state == "NEW"


def test_reopen_button_by_any_member(actor):
    other = make_member(email="other@westcode.de")
    f = make_finding(highest_severity="HIGH")
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=FakeSlack(), now=NOW)
    reopen(f, other, source="SLACK", note="Bitte nochmal prüfen", now=NOW)
    assert (f.state, f.dismissal_mode, f.dismissed_by) == ("NEW", "", None)
    assert f.events.filter(actor=other, source="SLACK", to_state="NEW").exists()


def test_cannot_dismiss_verified_finding(actor):
    with pytest.raises(ValidationError):
        dismiss(make_finding(state="VERIFIED_LIVE"), actor, mode="DISMISSED", reason=REASON, source="WEB",
                slack=FakeSlack(), now=NOW)
