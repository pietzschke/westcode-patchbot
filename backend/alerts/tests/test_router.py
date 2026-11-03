import json
from unittest.mock import MagicMock, patch

import pytest
from django.core import mail

from alerts.models import AlertFingerprint
from alerts.router import (
    HttpAlertTransport,
    build_weekly_digest,
    notify_critical_cve,
    notify_rollout_rollback,
)
from catalog.models import HostTarget, ServiceGroup
from fleet.models import Host
from rollouts.models import RolloutPlan


class FakeTransport:
    def __init__(self):
        self.slack_messages = []
        self.zammad_tickets = []
        self.emails = []

    def send_slack(self, text: str):
        self.slack_messages.append(text)

    def create_zammad_ticket(self, title: str, body: str, group: str = "Infra") -> str:
        self.zammad_tickets.append((title, body, group))
        return f"ZMD-{len(self.zammad_tickets)}"

    def send_email(self, recipient: str, subject: str, body: str):
        self.emails.append((recipient, subject, body))


@pytest.mark.django_db
def test_notify_critical_cve_deduplicates_zammad_and_slack():
    sg = ServiceGroup.objects.create(
        slug="plausible",
        display_name="Plausible Analytics",
        logo_key="plausible",
        category="action_required",
        current_version_summary="2.1.0",
        target_version="2.1.2",
        highest_cve_id="CVE-2026-3104",
        highest_severity="HIGH",
        summary_line="Auth-Bypass im Klick-Tracking behoben",
    )
    transport = FakeTransport()

    assert notify_critical_cve(sg, transport) is True
    assert notify_critical_cve(sg, transport) is False
    assert len(transport.zammad_tickets) == 1
    assert len(transport.slack_messages) == 1
    assert "CVE-2026-3104" in transport.zammad_tickets[0][0]

    fp = AlertFingerprint.objects.get(fingerprint="cve:plausible:CVE-2026-3104")
    assert fp.external_ref == "ZMD-1"


@pytest.mark.django_db
def test_notify_critical_cve_skips_when_no_cve_id():
    sg = ServiceGroup.objects.create(
        slug="traefik",
        display_name="Traefik",
        logo_key="traefik",
        category="ready_to_rollout",
        current_version_summary="3.1.0",
        target_version="3.1.2",
        highest_cve_id="",
        highest_severity="",
    )
    transport = FakeTransport()

    assert notify_critical_cve(sg, transport) is False
    assert transport.slack_messages == []
    assert transport.zammad_tickets == []


@pytest.mark.django_db
def test_notify_rollout_rollback_deduplicates_and_includes_logs():
    sg = ServiceGroup.objects.create(
        slug="plausible",
        display_name="Plausible Analytics",
        logo_key="plausible",
        category="action_required",
        current_version_summary="2.1.0",
        target_version="2.1.2",
        highest_cve_id="CVE-2026-3104",
        highest_severity="HIGH",
    )
    plan = RolloutPlan.objects.create(service_group=sg, status="ROLLED_BACK")
    transport = FakeTransport()
    logs = "ERROR: Container plausible exited with code 1 (Healthcheck HTTP 502)"

    assert notify_rollout_rollback(plan, logs, transport) is True
    assert notify_rollout_rollback(plan, logs, transport) is False
    assert len(transport.slack_messages) == 1
    assert len(transport.zammad_tickets) == 1
    assert "Plausible Analytics" in transport.zammad_tickets[0][0]
    assert "Healthcheck HTTP 502" in transport.zammad_tickets[0][1]

    fp = AlertFingerprint.objects.get(fingerprint=f"rollback:{plan.id}")
    assert fp.external_ref == "ZMD-1"


@pytest.mark.django_db
def test_build_weekly_digest_summarizes_services_and_hosts():
    sg_urgent = ServiceGroup.objects.create(
        slug="plausible",
        display_name="Plausible Analytics",
        logo_key="plausible",
        category="action_required",
        current_version_summary="2.1.0",
        target_version="2.1.2",
        highest_cve_id="CVE-2026-3104",
        highest_severity="HIGH",
        summary_line="Auth-Bypass im Klick-Tracking behoben",
    )
    sg_ready = ServiceGroup.objects.create(
        slug="postgres",
        display_name="PostgreSQL",
        logo_key="postgres",
        category="ready_to_rollout",
        current_version_summary="18.0",
        target_version="18.1",
        summary_line="Neue Version 18.1 bereit zum Ausrollen",
    )
    host_eol = Host.objects.create(
        slug="linklama",
        hostname="linklama.westcode.de",
        provider="hetzner",
        stack_name="hetzner-linklama",
        os_distro="ubuntu",
        os_version="20.04",
        is_os_eol=True,
    )
    host_dirty = Host.objects.create(
        slug="coder",
        hostname="coder.westcode.de",
        provider="hetzner",
        stack_name="hetzner-coder",
        os_distro="ubuntu",
        os_version="24.04",
        is_os_eol=False,
    )
    HostTarget.objects.create(
        service_group=sg_urgent,
        host=host_dirty,
        target_type="compose",
        working_dir="/opt/coder",
        compose_service="coder",
        running_version="2.1.0",
        target_version="2.1.2",
        git_clean=False,
    )

    digest = build_weekly_digest([sg_urgent, sg_ready], [host_eol, host_dirty])

    assert len(digest["action_required"]) == 1
    assert digest["action_required"][0]["slug"] == "plausible"
    assert len(digest["ready"]) == 1
    assert digest["ready"][0]["slug"] == "postgres"
    assert len(digest["eol_hosts"]) == 1
    assert digest["eol_hosts"][0]["hostname"] == "linklama.westcode.de"
    assert len(digest["dirty_git_hosts"]) == 1
    assert digest["dirty_git_hosts"][0]["hostname"] == "coder.westcode.de"
    assert "Westcode Patchbot" in digest["subject"]
    assert "Plausible Analytics" in digest["body"]
    assert "PostgreSQL" in digest["body"]
    assert "linklama.westcode.de" in digest["body"]
    assert "coder.westcode.de" in digest["body"]


@pytest.mark.django_db
def test_http_alert_transport_posts_slack_zammad_and_email():
    transport = HttpAlertTransport(
        slack_webhook_url="https://hooks.slack.com/services/T00/B00/X00",
        zammad_base_url="https://support.westcode.de",
        zammad_token="zammad-secret-token",
    )

    captured_requests = []

    def fake_urlopen(req, timeout=None):
        captured_requests.append((req, timeout))
        resp = MagicMock()
        resp.__enter__.return_value = resp
        resp.read.return_value = json.dumps({"id": 42, "number": "96042"}).encode("utf-8")
        return resp

    with patch("alerts.router.urllib.request.urlopen", side_effect=fake_urlopen):
        transport.send_slack("Kritische CVE erkannt")
        ticket_ref = transport.create_zammad_ticket(
            title="[Patchbot] CVE-2026-3104 auf Plausible",
            body="Bitte zeitnah ausrollen.",
            group="Infra",
        )

    assert ticket_ref == "96042"
    assert len(captured_requests) == 2

    slack_req, _ = captured_requests[0]
    assert slack_req.full_url == "https://hooks.slack.com/services/T00/B00/X00"
    assert json.loads(slack_req.data.decode("utf-8")) == {"text": "Kritische CVE erkannt"}

    zammad_req, _ = captured_requests[1]
    assert zammad_req.full_url == "https://support.westcode.de/api/v1/tickets"
    assert zammad_req.get_header("Authorization") == "Bearer zammad-secret-token"
    zammad_payload = json.loads(zammad_req.data.decode("utf-8"))
    assert zammad_payload["title"] == "[Patchbot] CVE-2026-3104 auf Plausible"
    assert zammad_payload["group"] == "Infra"
    assert zammad_payload["article"]["body"] == "Bitte zeitnah ausrollen."

    transport.send_email(
        recipient="infra@westcode.de",
        subject="Patchbot Wochen-Digest",
        body="Alle Dienste im Überblick.",
    )
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ["infra@westcode.de"]
    assert mail.outbox[0].subject == "Patchbot Wochen-Digest"
