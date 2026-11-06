"""Team editor: git commit e-mail aliases for blame-based ownership (review low #2)."""

import pytest
from rest_framework.test import APIClient

from inventory.models import TeamMember
from testing.factories import make_member, make_user_with_member


@pytest.fixture
def admin(db):
    user, _ = make_user_with_member(email="admin@westcode.de", is_admin=True)
    client = APIClient()
    client.force_login(user)
    return client


def test_git_commit_emails_are_saved_normalized(admin):
    member = make_member(email="anna@westcode.de")
    resp = admin.patch(f"/api/team/{member.id}/",
                       {"git_commit_emails": [" Anna@Users.Noreply.GitHub.com ", "anna@private.de", "anna@private.de"]},
                       format="json")
    assert resp.status_code == 200
    assert resp.json()["git_commit_emails"] == ["anna@users.noreply.github.com", "anna@private.de"]
    assert TeamMember.objects.get(id=member.id).git_commit_emails == ["anna@users.noreply.github.com", "anna@private.de"]


@pytest.mark.parametrize("value", ["anna@private.de", ["kein-at-zeichen"], [42], None])
def test_git_commit_emails_must_be_a_list_of_addresses(admin, value):
    member = make_member(email="anna@westcode.de")
    resp = admin.patch(f"/api/team/{member.id}/", {"git_commit_emails": value}, format="json")
    assert resp.status_code == 400
    assert "git_commit_emails" in resp.json()["detail"]
    assert TeamMember.objects.get(id=member.id).git_commit_emails == []
