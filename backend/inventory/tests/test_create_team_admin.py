import pytest
from django.core.management import CommandError, call_command

from inventory.entra import bind_team_member
from inventory.models import TeamMember


@pytest.mark.django_db
def test_create_team_admin_bootstraps_first_admin_who_can_then_sign_in():
    call_command("create_team_admin", "--email", " Anna.Admin@Westcode.de ", "--name", "Anna Admin",
                 "--default-infra-owner")

    member = TeamMember.objects.get()
    assert member.email == "anna.admin@westcode.de"
    assert member.name == "Anna Admin"
    assert member.is_admin is True
    assert member.is_active is True
    assert member.is_default_infra_owner is True

    # The first Entra login binds to the pre-created member instead of being rejected.
    bound = bind_team_member({"oid": "oid-anna", "email": "anna.admin@westcode.de"})
    assert bound.pk == member.pk


@pytest.mark.django_db
def test_create_team_admin_is_idempotent_and_promotes_existing_member():
    existing = TeamMember.objects.create(name="Bob", email="bob@westcode.de", is_active=False,
                                         slack_user_id="U123", layers=["application"])

    call_command("create_team_admin", "--email", "bob@westcode.de", "--name", "Bob B.")
    call_command("create_team_admin", "--email", "bob@westcode.de", "--name", "Bob B.")

    assert TeamMember.objects.count() == 1
    existing.refresh_from_db()
    assert existing.is_admin is True
    assert existing.is_active is True
    assert existing.name == "Bob B."
    # Unrelated fields are left untouched; a missing flag never revokes the infra-owner role.
    assert existing.slack_user_id == "U123"
    assert existing.layers == ["application"]
    assert existing.is_default_infra_owner is False


@pytest.mark.django_db
def test_create_team_admin_rejects_foreign_domains():
    with pytest.raises(CommandError, match="westcode.de"):
        call_command("create_team_admin", "--email", "eve@example.com", "--name", "Eve")
    with pytest.raises(CommandError, match="westcode.de"):
        call_command("create_team_admin", "--email", "eve@westcode.de.evil.com", "--name", "Eve")
    assert not TeamMember.objects.exists()


@pytest.mark.django_db
def test_create_team_admin_refuses_second_default_infra_owner():
    TeamMember.objects.create(name="Infra", email="infra@westcode.de", is_default_infra_owner=True)

    with pytest.raises(CommandError, match="default infra owner"):
        call_command("create_team_admin", "--email", "carl@westcode.de", "--name", "Carl",
                     "--default-infra-owner")
    assert not TeamMember.objects.filter(email="carl@westcode.de").exists()
