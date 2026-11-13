import pytest
from django.core.exceptions import ValidationError
from testing.factories import make_container, make_host, make_member, make_project, make_repo, make_user_with_member


@pytest.mark.django_db
def test_email_is_normalised_to_lowercase():
    assert make_member(email="Moritz.Pietzschke@westcode.de").email == "moritz.pietzschke@westcode.de"


@pytest.mark.django_db
def test_only_one_active_default_infra_owner():
    make_member(email="infra1@westcode.de", is_default_infra_owner=True)
    second = make_member(email="infra2@westcode.de", is_default_infra_owner=False)
    second.is_default_infra_owner = True
    with pytest.raises(ValidationError):
        second.full_clean()


@pytest.mark.django_db
def test_inactive_default_infra_owner_does_not_block_new_one():
    make_member(email="old@westcode.de", is_default_infra_owner=True, is_active=False)
    new = make_member(email="new@westcode.de")
    new.is_default_infra_owner = True
    new.full_clean()


@pytest.mark.django_db
def test_repository_defaults():
    repo = make_repo(full_name="westcoder/materialdatenbank", project=make_project(slug="wuerth"))
    assert repo.deployment_mode == "UNKNOWN"
    assert repo.default_branch == "main"
    assert repo.project.repositories.get() == repo


@pytest.mark.django_db
def test_hosts_and_containers_link_to_projects_and_repositories():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/materialdatenbank", project=wuerth)
    host = make_host(slug="mdb", project=wuerth)
    container = make_container(host, project=wuerth, repository=repo)
    assert list(wuerth.hosts.all()) == [host]
    assert list(wuerth.containers.all()) == [container]
    assert list(repo.running_containers.all()) == [container]


@pytest.mark.django_db
def test_user_with_member_is_linked_one_to_one():
    user, member = make_user_with_member(email="dev@westcode.de", is_admin=True)
    assert user.team_member == member
    assert member.is_admin is True
