import pytest

from inventory.matching import confirm_suggestion, link_containers_to_repositories, suggest_projects, sync_repositories
from inventory.models import RepositoryAsset
from testing.factories import make_container, make_host, make_project, make_repo
from testing.fakes import FakeGitHub


@pytest.mark.django_db
def test_sync_repositories_detects_archive_and_bot_config():
    gh = FakeGitHub(
        repos=[
            {"full_name": "westcoder/materialdatenbank", "default_branch": "main", "archived": False},
            {"full_name": "westcoder/old-site", "default_branch": "master", "archived": True},
        ],
        files={("westcoder/materialdatenbank", "renovate.json")},
    )
    result = sync_repositories(gh)
    mdb = RepositoryAsset.objects.get(full_name="westcoder/materialdatenbank")
    old = RepositoryAsset.objects.get(full_name="westcoder/old-site")
    assert result == {"created": 2, "updated": 0}
    assert mdb.has_bot_updates is True
    assert (old.is_archived, old.default_branch) == (True, "master")


@pytest.mark.django_db
def test_sync_repositories_keeps_manual_fields():
    wuerth = make_project(slug="wuerth")
    make_repo(full_name="westcoder/materialdatenbank", project=wuerth, deployment_mode="CONTAINER")
    sync_repositories(FakeGitHub(repos=[{"full_name": "westcoder/materialdatenbank", "default_branch": "main", "archived": False}]))
    repo = RepositoryAsset.objects.get()
    assert (repo.project, repo.deployment_mode) == (wuerth, "CONTAINER")


@pytest.mark.django_db
def test_containers_link_to_repository_via_oci_source():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/materialdatenbank", project=wuerth)
    container = make_container(make_host(slug="mdb"), oci_source="https://github.com/westcoder/materialdatenbank.git")
    foreign = make_container(make_host(slug="other"), oci_source="https://github.com/plausible/analytics")
    assert link_containers_to_repositories() == 1
    container.refresh_from_db()
    foreign.refresh_from_db()
    assert (container.repository, container.project) == (repo, wuerth)
    assert foreign.repository is None


@pytest.mark.django_db
def test_suggestions_never_assign_directly():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/wuerth-converter")
    host = make_host(slug="converter", hostname="converter.westcode.de")
    unrelated = make_repo(full_name="westcoder/random-tool")
    assert suggest_projects() == 2
    for asset in (repo, host, unrelated):
        asset.refresh_from_db()
    assert repo.suggested_project == wuerth and repo.project is None
    assert host.suggested_project == wuerth and host.project is None
    assert unrelated.suggested_project is None


@pytest.mark.django_db
def test_suggestion_by_project_slug_token():
    ses = make_project(slug="ses-sandmann")
    repo = make_repo(full_name="westcoder/ses-sandmann-portal")
    suggest_projects()
    repo.refresh_from_db()
    assert repo.suggested_project == ses


@pytest.mark.django_db
def test_confirm_suggestion_assigns_and_clears():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/wuerth-converter", suggested_project=wuerth)
    confirm_suggestion(repo)
    repo.refresh_from_db()
    assert repo.project == wuerth
    assert repo.suggested_project is None


@pytest.mark.django_db
def test_unassigned_containers_get_suggestions():
    wuerth = make_project(slug="wuerth")
    container = make_container(make_host(slug="x1"), compose_service="materialdatenbank")
    suggest_projects()
    container.refresh_from_db()
    assert (container.suggested_project, container.project) == (wuerth, None)


@pytest.mark.parametrize("image_tag", [
    "registry.local:5000/materialdatenbank@sha256:" + "a" * 64,
    "registry.local:5000/materialdatenbank:main",
    "registry.local:5000/materialdatenbank",
    "123456789012.dkr.ecr.eu-central-1.amazonaws.com/team/materialdatenbank:1.2.3@sha256:" + "b" * 64,
    "materialdatenbank:latest",
    "materialdatenbank",
])
def test_container_image_key_ignores_registry_port_tag_and_digest(image_tag):
    from fleet.models import HostContainer
    from inventory.matching import _keys_for_container

    container = HostContainer(image_tag=image_tag, compose_service="", working_dir="")
    assert _keys_for_container(container) == ["materialdatenbank"]
