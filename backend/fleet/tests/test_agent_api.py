import hashlib
import pytest
from rest_framework.test import APIClient
from fleet.models import Host


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
def test_agent_report_cannot_spoof_another_host_via_hostname(hosts):
    # Identity comes from the token only (spec §7.2): a foreign hostname in the payload is ignored and the
    # report lands on the token's own host, never on the named one.
    h1, t1, h2, _ = hosts
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {t1}")

    resp = client.post(
        "/api/agent/report/",
        data={"hostname": "masteroil.westcode.de", "os_distro": "ubuntu", "os_version": "24.04", "packages": [], "containers": []},
        format="json",
    )
    assert resp.status_code == 200
    h1.refresh_from_db()
    h2.refresh_from_db()
    assert h1.last_seen_at is not None and h1.os_version == "24.04"
    assert h2.last_seen_at is None and h2.os_version != "24.04"


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
def test_agent_endpoints_reject_missing_or_invalid_token(hosts):
    client = APIClient()

    resp_missing = client.post("/api/agent/report/", data={}, format="json")
    assert resp_missing.status_code in (401, 403)

    client.credentials(HTTP_AUTHORIZATION="Bearer wrong-token")
    resp_invalid = client.post("/api/agent/report/", data={}, format="json")
    assert resp_invalid.status_code in (401, 403)
