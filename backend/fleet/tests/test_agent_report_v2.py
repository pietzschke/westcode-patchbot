import hashlib
from datetime import datetime, timezone
import pytest
from rest_framework.test import APIClient
from fleet.infra_sync import DISTRO_EOL_DATES
from fleet.models import Host

TOKEN = "tok-mdb-secret"


@pytest.fixture
def host(db):
    return Host.objects.create(
        slug="mdb", hostname="mdb.westcode.de", provider="hetzner", stack_name="hetzner-mdb",
        agent_token_hash=hashlib.sha256(TOKEN.encode()).hexdigest(),
    )


def _post(payload):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {TOKEN}")
    return client.post("/api/agent/report/", data=payload, format="json")


REPORT = {
    "hostname": "mdb.westcode.de",
    "os_distro": "ubuntu",
    "os_version": "20.04",
    "kernel_version": "5.4.0-200-generic",
    "agent_version": "2.0.0",
    "apt_lists_updated_at": "2026-11-05T03:00:00+00:00",
    "reboot_required": False,
    "packages": [
        {"name": "openssl", "installed_version": "1.1.1f-1ubuntu2.22", "candidate_version": "1.1.1f-1ubuntu2.23",
         "is_security_update": True, "source_pocket": "focal-security"},
        {"name": "libc6", "installed_version": "2.31-0ubuntu9.16", "candidate_version": "",
         "is_security_update": False, "source_pocket": ""},
    ],
    "containers": [{
        "container_id": "c1", "name": "mdb-app", "image_tag": "ecr/materialdatenbank:main", "image_id": "sha256:img1",
        "repo_digests": ["ecr/materialdatenbank@sha256:d1"],
        "oci_revision": "abc123", "oci_source": "https://github.com/westcoder/materialdatenbank",
        "image_created_at": "2026-11-04T09:15:00.123456789Z",
        "working_dir": "/opt/mdb", "compose_service": "app", "git_head_sha": "f00dfeed", "git_clean": True,
        "status": "running",
    }],
}


def test_report_persists_v2_host_fields(host):
    assert _post(REPORT).status_code == 200
    host.refresh_from_db()
    assert host.kernel_version == "5.4.0-200-generic"
    assert host.agent_version == "2.0.0"
    assert host.apt_lists_updated_at == datetime(2026, 11, 5, 3, 0, tzinfo=timezone.utc)
    assert host.os_eol_date == DISTRO_EOL_DATES[("ubuntu", "20.04")]
    assert host.packages.count() == 2
    assert host.packages.get(name="openssl").source_pocket == "focal-security"
    assert host.packages.get(name="libc6").candidate_version == ""


def test_report_persists_v2_container_fields(host):
    _post(REPORT)
    c = host.containers.get()
    assert c.oci_source == "https://github.com/westcoder/materialdatenbank"
    assert c.image_created_at == datetime(2026, 11, 4, 9, 15, 0, 123456, tzinfo=timezone.utc)
    assert c.git_head_sha == "f00dfeed"
    assert c.reported_at is not None


def test_report_replaces_containers_in_full(host):
    _post(REPORT)
    _post({**REPORT, "containers": []})
    assert host.containers.count() == 0


def test_invalid_timestamps_are_stored_as_null(host):
    bad = {**REPORT, "apt_lists_updated_at": "yesterday",
           "containers": [{**REPORT["containers"][0], "image_created_at": "n/a"}]}
    assert _post(bad).status_code == 200
    host.refresh_from_db()
    assert host.apt_lists_updated_at is None
    assert host.containers.get().image_created_at is None


def test_unknown_distro_has_no_eol_date(host):
    _post({**REPORT, "os_distro": "alpine", "os_version": "3.20"})
    host.refresh_from_db()
    assert host.os_eol_date is None
