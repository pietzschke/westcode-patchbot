"""Project ↔ asset editor on /projects (spec v2.1 §8.1, review H-9)."""

import pytest
from rest_framework.test import APIClient

from fleet.models import HostContainer
from testing.factories import make_container, make_host, make_project, make_repo, make_user_with_member


@pytest.fixture
def admin(db):
    user, _ = make_user_with_member(email="admin@westcode.de", is_admin=True)
    client = APIClient()
    client.force_login(user)
    return client


def test_project_lists_assigned_containers(admin):
    wuerth = make_project(slug="wuerth", name="Würth")
    host = make_host(slug="mdb")
    make_container(host, name="app", project=wuerth)
    make_container(host, name="db")
    body = admin.get("/api/triage-projects/").json()
    project = next(p for p in body["projects"] if p["slug"] == "wuerth")
    assert [c["name"] for c in project["containers"]] == ["mdb.westcode.de: app"]
    assert project["containers"][0]["type"] == "container"
    assert [c["name"] for c in body["unassigned_assets"]["containers"]] == ["mdb.westcode.de: db"]


def test_assigned_asset_can_be_reassigned_and_unassigned(admin):
    wuerth = make_project(slug="wuerth")
    ses = make_project(slug="ses")
    container = make_container(make_host(), project=wuerth)
    assert admin.post(f"/api/assets/container/{container.id}/assign/", {"project_slug": "ses"},
                      format="json").status_code == 200
    container.refresh_from_db()
    assert container.project == ses
    assert admin.post(f"/api/assets/container/{container.id}/assign/", {"project_slug": None},
                      format="json").status_code == 200
    container.refresh_from_db()
    assert container.project is None


def test_assigning_repository_moves_its_unassigned_containers_along(admin):
    wuerth = make_project(slug="wuerth")
    other = make_project(slug="other")
    repo = make_repo(full_name="westcoder/materialdatenbank")
    host = make_host()
    linked = make_container(host, repository=repo)
    already_assigned = make_container(host, repository=repo, project=other)
    unrelated = make_container(host)
    assert admin.post(f"/api/assets/repository/{repo.id}/assign/", {"project_slug": "wuerth"},
                      format="json").status_code == 200
    projects = dict(HostContainer.objects.values_list("id", "project__slug"))
    assert projects[linked.id] == "wuerth"
    assert projects[already_assigned.id] == "other"
    assert projects[unrelated.id] is None
    assert wuerth.containers.count() == 1


def test_confirming_repository_suggestion_moves_its_unassigned_containers_along(admin):
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/wuerth-converter", suggested_project=wuerth)
    container = make_container(make_host(), repository=repo)
    assert admin.post(f"/api/assets/repository/{repo.id}/confirm-suggestion/").status_code == 200
    container.refresh_from_db()
    assert container.project == wuerth
