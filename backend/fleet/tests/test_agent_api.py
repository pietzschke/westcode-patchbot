import hashlib
import pytest
from rest_framework.test import APIClient
from fleet.models import AgentJob, Host


@pytest.fixture
def hosts(db):
    t1 = "tok-linklama-secret"
    t2 = "tok-masteroil-secret"
    h1 = Host.objects.create(
        slug="linklama",
        hostname="linklama.westcode.de",
        provider="hetzner",
        stack_name="hetzner-linklama",
        agent_token_hash=hashlib.sha256(t1.encode()).hexdigest(),
    )
    h2 = Host.objects.create(
        slug="masteroil",
        hostname="masteroil.westcode.de",
        provider="hetzner",
        stack_name="hetzner-masteroil",
        agent_token_hash=hashlib.sha256(t2.encode()).hexdigest(),
    )
    return (h1, t1, h2, t2)


@pytest.mark.django_db
def test_agent_report_rejects_cross_host_spoofing(hosts):
    h1, t1, h2, _ = hosts
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {t1}")

    resp = client.post(
        "/api/agent/report/",
        data={"hostname": "masteroil.westcode.de", "os_distro": "ubuntu", "os_version": "24.04", "packages": [], "containers": []},
        format="json",
    )
    assert resp.status_code == 403


@pytest.mark.django_db
def test_agent_report_persists_packages_and_containers(hosts):
    h1, t1, _, _ = hosts
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {t1}")

    resp = client.post(
        "/api/agent/report/",
        data={
            "hostname": "linklama.westcode.de",
            "os_distro": "ubuntu",
            "os_version": "20.04",
            "reboot_required": True,
            "packages": [
                {"name": "openssl", "installed_version": "1.1.1f", "candidate_version": "1.1.1f-2", "is_security_update": True}
            ],
            "containers": [
                {
                    "container_id": "c1",
                    "name": "hub-backend-1",
                    "image_tag": "hub-backend",
                    "image_id": "sha256:abc",
                    "repo_digests": ["069962555850.dkr.ecr.eu-central-1.amazonaws.com/westcode-hub@sha256:deadbeef"],
                    "oci_title": "westcode-hub",
                    "oci_revision": "8f3a1c",
                    "working_dir": "/opt/hub",
                    "compose_service": "backend",
                    "git_clean": True,
                    "status": "running",
                }
            ],
        },
        format="json",
    )
    assert resp.status_code == 200
    h1.refresh_from_db()
    assert h1.is_os_eol is True
    assert h1.reboot_required is True
    assert h1.last_seen_at is not None
    assert h1.packages.count() == 1
    assert h1.containers.get().oci_title == "westcode-hub"


@pytest.mark.django_db
def test_agent_next_job_returns_only_own_pending_jobs_and_marks_dispatched(hosts):
    h1, t1, h2, _ = hosts
    other_job = AgentJob.objects.create(
        host=h2,
        action_type="apt_upgrade",
        payload={},
        status="PENDING",
    )
    own_job_1 = AgentJob.objects.create(
        host=h1,
        action_type="precheck",
        payload={"working_dir": "/opt/linklama", "target_image": "linklama:v2"},
        status="PENDING",
    )
    own_job_2 = AgentJob.objects.create(
        host=h1,
        action_type="compose_update",
        payload={"working_dir": "/opt/linklama", "service": "web", "target_image": "linklama:v2"},
        status="PENDING",
    )

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {t1}")

    resp1 = client.get("/api/agent/jobs/next/")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["id"] == str(own_job_1.id)
    assert data1["action_type"] == "precheck"
    own_job_1.refresh_from_db()
    assert own_job_1.status == "DISPATCHED"

    resp2 = client.get("/api/agent/jobs/next/")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["id"] == str(own_job_2.id)
    own_job_2.refresh_from_db()
    assert own_job_2.status == "DISPATCHED"

    # No more PENDING jobs for h1; h2's job must remain untouched
    resp3 = client.get("/api/agent/jobs/next/")
    assert resp3.status_code in (200, 204)
    if resp3.status_code == 200:
        assert not resp3.json().get("id")
    other_job.refresh_from_db()
    assert other_job.status == "PENDING"


@pytest.mark.django_db
def test_agent_job_result_enforces_host_isolation_and_records_outcome(hosts):
    h1, t1, h2, _ = hosts
    own_job = AgentJob.objects.create(
        host=h1,
        action_type="compose_update",
        payload={"working_dir": "/opt/linklama"},
        status="DISPATCHED",
    )
    other_job = AgentJob.objects.create(
        host=h2,
        action_type="compose_update",
        payload={"working_dir": "/opt/masteroil"},
        status="DISPATCHED",
    )

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {t1}")

    # Attempt to post result for h2's job using h1's token -> rejected (403)
    cross_resp = client.post(
        f"/api/agent/jobs/{other_job.id}/result/",
        data={"status": "SUCCEEDED", "result_payload": {"logs": "spoofed"}},
        format="json",
    )
    assert cross_resp.status_code == 403
    other_job.refresh_from_db()
    assert other_job.status == "DISPATCHED"
    assert other_job.result_payload == {}

    # Post result for own job -> accepted and persisted
    own_resp = client.post(
        f"/api/agent/jobs/{own_job.id}/result/",
        data={
            "status": "ROLLED_BACK",
            "result_payload": {"prev_image_id": "sha256:old", "logs": "healthcheck timed out"},
        },
        format="json",
    )
    assert own_resp.status_code == 200
    own_job.refresh_from_db()
    assert own_job.status == "ROLLED_BACK"
    assert own_job.result_payload == {"prev_image_id": "sha256:old", "logs": "healthcheck timed out"}


@pytest.mark.django_db
def test_agent_endpoints_reject_missing_or_invalid_token(hosts):
    client = APIClient()

    resp_missing = client.get("/api/agent/jobs/next/")
    assert resp_missing.status_code in (401, 403)

    client.credentials(HTTP_AUTHORIZATION="Bearer wrong-token")
    resp_invalid = client.get("/api/agent/jobs/next/")
    assert resp_invalid.status_code in (401, 403)

