from datetime import date, datetime, timezone

import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from fleet.models import HostPackage
from testing.factories import make_container, make_host, make_project, make_user_with_member


def _client(*, is_admin: bool = False) -> APIClient:
    user, _ = make_user_with_member(is_admin=is_admin)
    client = APIClient()
    client.force_login(user)
    return client


def _host_payload(client: APIClient, slug: str) -> dict:
    hosts = client.get("/api/hosts/").json()
    return next(h for h in hosts if h["slug"] == slug)


@pytest.mark.django_db
def test_only_upgrade_candidates_count_as_pending():
    host = make_host(slug="mdb")
    HostPackage.objects.create(host=host, name="bash", installed_version="5.1-6ubuntu1")
    HostPackage.objects.create(host=host, name="coreutils", installed_version="8.32-4.1ubuntu1")
    HostPackage.objects.create(
        host=host,
        name="openssl",
        installed_version="3.0.2-0ubuntu1.10",
        candidate_version="3.0.2-0ubuntu1.15",
        is_security_update=True,
        source_pocket="jammy-security",
    )
    HostPackage.objects.create(
        host=host,
        name="tzdata",
        installed_version="2024a-0ubuntu0.22.04",
        candidate_version="2024b-0ubuntu0.22.04",
        source_pocket="jammy-updates",
    )

    data = _host_payload(_client(), "mdb")

    assert data["pending_apt_count"] == 2
    assert data["actionable_packages_count"] == 2
    assert data["security_apt_count"] == 1
    assert data["installed_package_count"] == 4
    assert [p["name"] for p in data["packages"]] == ["openssl", "tzdata"]
    assert data["packages"][0]["source_pocket"] == "jammy-security"
    assert data["packages"][0]["candidate_version"] == "3.0.2-0ubuntu1.15"


@pytest.mark.django_db
def test_installed_only_security_flag_is_not_counted():
    host = make_host(slug="web")
    HostPackage.objects.create(host=host, name="libc6", installed_version="2.35", is_security_update=True)

    data = _host_payload(_client(), "web")

    assert data["pending_apt_count"] == 0
    assert data["security_apt_count"] == 0
    assert data["packages"] == []
    assert data["installed_package_count"] == 1


@pytest.mark.django_db
def test_host_exposes_v2_telemetry_fields():
    project = make_project(slug="wuerth", name="Würth")
    make_host(
        slug="mdb",
        kernel_version="5.15.0-113-generic",
        agent_version="2.0.0",
        apt_lists_updated_at=datetime(2026, 11, 4, 6, 0, tzinfo=timezone.utc),
        os_eol_date=date(2027, 4, 30),
        project=project,
    )
    make_host(slug="bare")
    client = _client()

    data = _host_payload(client, "mdb")
    assert data["kernel_version"] == "5.15.0-113-generic"
    assert data["agent_version"] == "2.0.0"
    assert data["apt_lists_updated_at"] == "2026-11-04T06:00:00+00:00"
    assert data["os_eol_date"] == "2027-04-30"
    assert data["project"] == {"slug": "wuerth", "name": "Würth"}

    bare = _host_payload(client, "bare")
    assert bare["apt_lists_updated_at"] is None
    assert bare["os_eol_date"] is None
    assert bare["project"] is None


@pytest.mark.django_db
def test_container_exposes_provenance_fields():
    host = make_host(slug="mdb")
    make_container(
        host,
        name="mdb-web",
        oci_source="https://github.com/westcoder/materialdatenbank",
        oci_revision="abc123",
        image_created_at=datetime(2026, 11, 1, 12, 30, tzinfo=timezone.utc),
        git_head_sha="def456",
        git_clean=False,
        repo_digests=["ghcr.io/westcoder/mdb@sha256:deadbeef"],
    )
    make_container(host, name="mdb-worker")

    containers = {c["name"]: c for c in _host_payload(_client(), "mdb")["containers"]}

    web = containers["mdb-web"]
    assert web["oci_source"] == "https://github.com/westcoder/materialdatenbank"
    assert web["image_created_at"] == "2026-11-01T12:30:00+00:00"
    assert web["git_head_sha"] == "def456"
    assert web["git_clean"] is False
    assert web["repo_digests"] == ["ghcr.io/westcoder/mdb@sha256:deadbeef"]
    assert containers["mdb-worker"]["image_created_at"] is None
    assert containers["mdb-worker"]["repo_digests"] == []


@pytest.mark.django_db
@override_settings(PATCHBOT_BASE_URL="https://patch.westcode.de")
def test_install_command_passes_env_vars_with_configured_base_url():
    make_host(slug="mdb", hostname="mdb.westcode.de")

    resp = _client(is_admin=True).post("/api/hosts/mdb/token/")

    assert resp.status_code == 200
    body = resp.json()
    assert body["install_command"] == (
        f"sudo PATCHBOT_URL=https://patch.westcode.de PATCHBOT_TOKEN={body['token']} "
        "PATCHBOT_HOSTNAME=mdb.westcode.de ./deploy/install-agent.sh"
    )


@pytest.mark.django_db
@override_settings(PATCHBOT_BASE_URL="")
def test_install_command_falls_back_to_request_host():
    make_host(slug="mdb", hostname="mdb.westcode.de")

    resp = _client(is_admin=True).post("/api/hosts/mdb/token/")

    body = resp.json()
    assert body["install_command"] == (
        f"sudo PATCHBOT_URL=http://testserver PATCHBOT_TOKEN={body['token']} "
        "PATCHBOT_HOSTNAME=mdb.westcode.de ./deploy/install-agent.sh"
    )
