import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import pytest
from rest_framework.test import APIClient

from triage.models import WebhookEvent
from triage.webhooks import process_pending_webhooks, process_webhook_event, reconcile_open_prs
from testing.factories import make_finding, make_member
from testing.fakes import FakeGitHub, FakeSlack

SLACK_SECRET = "slack-secret"
GH_SECRET = "gh-secret"
SLACK_PATH = "/api/webhooks/slack/interactions/"
GH_PATH = "/api/webhooks/github/"
NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def secrets(settings):
    settings.SLACK_SIGNING_SECRET = SLACK_SECRET
    settings.GITHUB_WEBHOOK_SECRET = GH_SECRET


def slack_sig(ts, body):
    return "v0=" + hmac.new(SLACK_SECRET.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()


def post_slack(payload, *, ts=None, sig=None):
    ts = str(ts or int(time.time()))
    body = urlencode({"payload": json.dumps(payload)})
    client = APIClient(enforce_csrf_checks=True)
    return client.generic("POST", SLACK_PATH, body, content_type="application/x-www-form-urlencoded",
                          HTTP_X_SLACK_REQUEST_TIMESTAMP=ts, HTTP_X_SLACK_SIGNATURE=sig or slack_sig(ts, body))


def post_github(payload, *, delivery="d-1", sig=None, event="pull_request"):
    body = json.dumps(payload)
    signature = sig or "sha256=" + hmac.new(GH_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    client = APIClient(enforce_csrf_checks=True)
    return client.generic("POST", GH_PATH, body, content_type="application/json",
                          HTTP_X_HUB_SIGNATURE_256=signature, HTTP_X_GITHUB_DELIVERY=delivery, HTTP_X_GITHUB_EVENT=event)


def action_payload(finding_id, slack_user="UA", action="ack"):
    return {"type": "block_actions", "user": {"id": slack_user},
            "actions": [{"action_id": action, "value": str(finding_id)}]}


def process_one(gh=None):
    event = WebhookEvent.objects.get()
    process_webhook_event(event, github=gh or FakeGitHub(), slack=FakeSlack(), now=NOW)
    event.refresh_from_db()
    return event


@pytest.mark.django_db
def test_slack_valid_signature_is_enqueued_without_session_or_csrf():
    assert post_slack(action_payload(1)).status_code == 200
    event = WebhookEvent.objects.get()
    assert (event.source, event.status) == ("SLACK", "PENDING")


@pytest.mark.django_db
def test_slack_invalid_signature_rejected():
    assert post_slack(action_payload(1), sig="v0=deadbeef").status_code == 401
    assert WebhookEvent.objects.count() == 0


@pytest.mark.django_db
def test_slack_replayed_timestamp_rejected():
    assert post_slack(action_payload(1), ts=int(time.time()) - 301).status_code == 401


@pytest.mark.django_db
def test_missing_secret_fails_closed(settings):
    settings.SLACK_SIGNING_SECRET = ""
    assert post_slack(action_payload(1)).status_code == 401


@pytest.mark.django_db
def test_get_is_not_allowed():
    assert APIClient().get(SLACK_PATH).status_code == 405


@pytest.mark.django_db
def test_slack_ack_from_known_user_acknowledges():
    member = make_member(email="a@westcode.de", slack_user_id="UA")
    f = make_finding(state="NEW", assignee=member)
    post_slack(action_payload(f.id, "UA"))
    assert process_one().status == "PROCESSED"
    f.refresh_from_db()
    assert f.state == "IN_PROGRESS"
    assert f.events.filter(source="SLACK", actor=member).exists()


@pytest.mark.django_db
def test_slack_reopen_button():
    make_member(email="a@westcode.de", slack_user_id="UA")
    f = make_finding(state="DISMISSED", highest_severity="HIGH")
    post_slack(action_payload(f.id, "UA", action="reopen"))
    process_one()
    f.refresh_from_db()
    assert f.state == "NEW"


@pytest.mark.django_db
def test_slack_action_from_unknown_user_rejected():
    f = make_finding(state="NEW")
    post_slack(action_payload(f.id, "U-STRANGER"))
    event = process_one()
    f.refresh_from_db()
    assert f.state == "NEW"
    assert event.status == "REJECTED"


@pytest.mark.django_db
def test_github_invalid_signature_rejected():
    assert post_github({"action": "closed"}, sig="sha256=00").status_code == 401


@pytest.mark.django_db
def test_github_duplicate_delivery_is_ignored():
    post_github({"action": "closed"}, delivery="d-7")
    assert post_github({"action": "closed"}, delivery="d-7").status_code == 200
    assert WebhookEvent.objects.count() == 1


@pytest.mark.django_db
def test_github_processing_trusts_api_not_payload():
    f = make_finding(state="IN_PROGRESS", pr_number=41, repository__full_name="westcoder/mdb")
    payload = {"action": "closed", "repository": {"full_name": "westcoder/mdb"},
               "pull_request": {"number": 41, "merged": True, "merge_commit_sha": "forged"}}
    post_github(payload)
    process_one(FakeGitHub(pull_details={("westcoder/mdb", 41): {"state": "open", "merged": False}}))
    f.refresh_from_db()
    assert f.state == "IN_PROGRESS"


@pytest.mark.django_db
def test_github_merge_is_applied_with_api_values():
    f = make_finding(state="IN_PROGRESS", pr_number=41, repository__full_name="westcoder/mdb")
    post_github({"action": "closed", "repository": {"full_name": "westcoder/mdb"}, "pull_request": {"number": 41}})
    gh = FakeGitHub(pull_details={("westcoder/mdb", 41): {
        "state": "closed", "merged": True, "merged_at": "2026-11-09T08:00:00Z", "merge_commit_sha": "m1"}})
    process_one(gh)
    f.refresh_from_db()
    assert (f.state, f.merge_commit_sha) == ("PR_MERGED_WAITING_LIVE", "m1")
    assert f.pr_merged_at == datetime(2026, 11, 9, 8, 0, tzinfo=timezone.utc)
    assert f.events.filter(source="GITHUB").exists()


@pytest.mark.django_db
def test_process_pending_handles_each_event_once():
    member = make_member(email="a@westcode.de", slack_user_id="UA")
    f = make_finding(state="NEW", assignee=member)
    post_slack(action_payload(f.id, "UA"))
    assert process_pending_webhooks(github=FakeGitHub(), slack=FakeSlack(), now=NOW) == 1
    assert process_pending_webhooks(github=FakeGitHub(), slack=FakeSlack(), now=NOW) == 0


@pytest.mark.django_db
def test_reconciliation_poll_catches_missed_merge():
    f = make_finding(state="IN_PROGRESS", pr_number=41, repository__full_name="westcoder/mdb")
    make_finding(state="IN_PROGRESS", pr_number=42, repository__full_name="westcoder/other")
    gh = FakeGitHub(pull_details={("westcoder/mdb", 41): {
        "state": "closed", "merged": True, "merged_at": "2026-11-09T08:00:00Z", "merge_commit_sha": "m1"}})
    assert reconcile_open_prs(github=gh, now=NOW) == 1
    f.refresh_from_db()
    assert (f.state, f.merge_commit_sha) == ("PR_MERGED_WAITING_LIVE", "m1")


@pytest.mark.django_db
def test_reconciliation_refreshes_ci_status_of_open_prs():
    f = make_finding(state="IN_PROGRESS", pr_number=41, pr_head_ref="patchbot/lodash-4.17.21",
                     repository__full_name="westcoder/mdb")
    gh = FakeGitHub(ci_status={("westcoder/mdb", "patchbot/lodash-4.17.21"): "failure"})
    assert reconcile_open_prs(github=gh, now=NOW) == 0
    f.refresh_from_db()
    assert f.ci_status == "failure"


@pytest.mark.django_db
def test_reconciliation_survives_a_failing_pull_request():
    broken = make_finding(state="IN_PROGRESS", pr_number=40, repository__full_name="westcoder/broken")
    f = make_finding(state="IN_PROGRESS", pr_number=41, repository__full_name="westcoder/mdb")

    class FlakyGitHub(FakeGitHub):
        def get_pull(self, repo, number):
            if repo == "westcoder/broken":
                raise RuntimeError("GitHub 502")
            return super().get_pull(repo, number)

    gh = FlakyGitHub(pull_details={("westcoder/mdb", 41): {
        "state": "closed", "merged": True, "merged_at": "2026-11-09T08:00:00Z", "merge_commit_sha": "m1"}})
    assert reconcile_open_prs(github=gh, now=NOW) == 1
    f.refresh_from_db()
    broken.refresh_from_db()
    assert (f.state, broken.state) == ("PR_MERGED_WAITING_LIVE", "IN_PROGRESS")
