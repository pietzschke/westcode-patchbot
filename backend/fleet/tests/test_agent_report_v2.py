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


def test_report_keeps_container_assignments_across_reports(host):
    from fleet.models import HostContainer
    from testing.factories import make_project, make_repo

    _post({**REPORT, "containers": [{**REPORT["containers"][0], "oci_source": ""}]})
    project = make_project()
    repo = make_repo(project=project)
    HostContainer.objects.filter(host=host).update(project=project, suggested_project=project, repository=repo)
    original_id = host.containers.get().id

    # Container was recreated (new id/digest) between reports — same name + compose service.
    second = {**REPORT["containers"][0], "container_id": "c1-new", "image_id": "sha256:img2", "oci_source": ""}
    assert _post({**REPORT, "containers": [second]}).status_code == 200

    c = host.containers.get()
    assert c.id == original_id
    assert c.project_id == project.id
    assert c.suggested_project_id == project.id
    assert c.repository_id == repo.id
    assert c.container_id == "c1-new"
    assert c.image_id == "sha256:img2"


def test_report_updates_reported_at_for_existing_container(host):
    _post(REPORT)
    first = host.containers.get().reported_at
    _post(REPORT)
    assert host.containers.get().reported_at > first


def test_new_container_links_to_known_repository_immediately(host):
    from testing.factories import make_project, make_repo

    project = make_project()
    repo = make_repo(full_name="westcoder/materialdatenbank", project=project)
    _post(REPORT)
    c = host.containers.get()
    assert c.repository_id == repo.id
    assert c.project_id == project.id


def test_changed_oci_source_relinks_repository(host):
    from testing.factories import make_repo

    old = make_repo(full_name="westcoder/materialdatenbank")
    new = make_repo(full_name="westcoder/mdb-next")
    _post(REPORT)
    assert host.containers.get().repository_id == old.id
    moved = {**REPORT["containers"][0], "oci_source": "https://github.com/westcoder/mdb-next"}
    _post({**REPORT, "containers": [moved]})
    assert host.containers.get().repository_id == new.id


def test_vanished_containers_are_removed_others_kept(host):
    from testing.factories import make_project

    worker = {**REPORT["containers"][0], "container_id": "c2", "name": "mdb-worker", "compose_service": "worker"}
    _post({**REPORT, "containers": [REPORT["containers"][0], worker]})
    project = make_project()
    host.containers.filter(name="mdb-app").update(project=project)
    _post(REPORT)
    assert list(host.containers.values_list("name", "project_id")) == [("mdb-app", project.id)]
