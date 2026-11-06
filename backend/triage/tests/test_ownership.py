from datetime import datetime, timezone

import pytest

from triage.ownership import assign, resolve_assignee
from testing.factories import make_finding, make_member, make_project, make_repo
from testing.fakes import FakeGitHub

NOW = datetime(2026, 11, 5, 7, 0, tzinfo=timezone.utc)


@pytest.fixture
def team(db):
    return {
        "infra": make_member(email="infra@westcode.de", is_default_infra_owner=True, slack_user_id="U1"),
        "owner": make_member(email="owner@westcode.de", slack_user_id="U2"),
        "dev": make_member(email="dev@westcode.de", github_username="dev-gh", slack_user_id="U3"),
        "alias": make_member(email="alias@westcode.de", git_commit_emails=["alias@users.noreply.github.com"], slack_user_id="U4"),
        "gone": make_member(email="gone@westcode.de", github_username="gone-gh", is_active=False, slack_user_id="U5"),
    }


def test_infrastructure_goes_to_default_infra_owner(team):
    f = make_finding(layer="INFRASTRUCTURE")
    assert resolve_assignee(f, github=FakeGitHub(), now=NOW)[0] == team["infra"]


def test_container_image_goes_to_project_owner(team):
    f = make_finding(layer="CONTAINER_IMAGE", project=make_project(owner=team["owner"]))
    assert resolve_assignee(f, github=FakeGitHub(), now=NOW)[0] == team["owner"]


def test_simple_application_ignores_lockfile_authors(team):
    gh = FakeGitHub(authors=[{"login": "dev-gh", "email": "dev@westcode.de", "date": NOW}])
    f = make_finding(layer="APPLICATION", complexity="SIMPLE", project=make_project(owner=team["owner"]))
    assert resolve_assignee(f, github=gh, now=NOW)[0] == team["owner"]
    assert gh.author_queries == []


def test_complex_application_picks_newest_active_human(team):
    gh = FakeGitHub(authors=[
        {"login": "renovate[bot]", "email": "bot@renovateapp.com", "date": NOW},
        {"login": "gone-gh", "email": "gone@westcode.de", "date": NOW},
        {"login": None, "email": "alias@users.noreply.github.com", "date": NOW},
        {"login": "dev-gh", "email": "dev@westcode.de", "date": NOW},
    ])
    project = make_project(owner=team["owner"])
    f = make_finding(layer="APPLICATION", complexity="COMPLEX", affected_files=["src/api.ts:12", "src/api.ts:40"],
                     project=project, repository=make_repo(project=project, full_name="westcoder/mdb"))
    member, reason = resolve_assignee(f, github=gh, now=NOW)
    assert member == team["alias"]
    assert "Git" in reason
    assert gh.author_queries[0]["repo"] == "westcoder/mdb"
    assert gh.author_queries[0]["paths"] == ["src/api.ts"]
    assert gh.author_queries[0]["since"] == datetime(2025, 11, 5, 7, 0, tzinfo=timezone.utc)


def test_falls_back_to_project_owner(team):
    gh = FakeGitHub(authors=[{"login": "dependabot[bot]", "email": "x", "date": NOW}])
    f = make_finding(layer="APPLICATION", complexity="COMPLEX", affected_files=["a.py:1"],
                     project=make_project(owner=team["owner"]))
    member, reason = resolve_assignee(f, github=gh, now=NOW)
    assert member == team["owner"]
    assert "Projekt" in reason


def test_owner_without_slack_is_unassigned(team):
    no_slack = make_member(email="noslack@westcode.de", slack_user_id=None)
    f = make_finding(layer="CONTAINER_IMAGE", project=make_project(owner=no_slack))
    member, reason = resolve_assignee(f, github=FakeGitHub(), now=NOW)
    assert member is None
    assert "Slack" in reason


def test_no_owner_at_all_is_unassigned(db):
    member, reason = resolve_assignee(make_finding(layer="INFRASTRUCTURE"), github=FakeGitHub(), now=NOW)
    assert member is None
    assert reason


def test_assign_persists_and_logs_once(team):
    f = make_finding(layer="INFRASTRUCTURE")
    assign(f, github=FakeGitHub(), now=NOW)
    assign(f, github=FakeGitHub(), now=NOW)
    f.refresh_from_db()
    assert f.assignee == team["infra"]
    assert f.events.filter(note__icontains="Zugewiesen").count() == 1


def test_assign_keeps_taken_over_assignee(team):
    from triage.lifecycle import acknowledge

    f = make_finding(layer="CONTAINER_IMAGE", project=make_project(owner=team["owner"]))
    assign(f, github=FakeGitHub(), now=NOW)
    acknowledge(f, team["dev"], source="WEB", now=NOW)
    assign(f, github=FakeGitHub(), now=NOW)
    f.refresh_from_db()
    assert (f.state, f.assignee, f.assigned_reason_de) == ("IN_PROGRESS", team["dev"], "Per „Ich bin dran“ übernommen")


@pytest.mark.parametrize("change", [{"is_active": False}, {"slack_user_id": None}])
def test_assign_replaces_unreachable_acknowledged_assignee(team, change):
    from triage.lifecycle import acknowledge

    f = make_finding(layer="CONTAINER_IMAGE", project=make_project(owner=team["owner"]))
    acknowledge(f, team["dev"], source="WEB", now=NOW)
    for field, value in change.items():
        setattr(team["dev"], field, value)
    team["dev"].save()
    assign(f, github=FakeGitHub(), now=NOW)
    f.refresh_from_db()
    assert f.assignee == team["owner"]


def test_git_author_without_slack_falls_back_to_project_owner(team):
    make_member(email="quiet@westcode.de", github_username="quiet-gh", slack_user_id=None)
    gh = FakeGitHub(authors=[{"login": "quiet-gh", "email": "quiet@westcode.de", "date": NOW}])
    project = make_project(owner=team["owner"])
    f = make_finding(layer="APPLICATION", complexity="COMPLEX", affected_files=["src/api.ts:12"],
                     project=project, repository=make_repo(project=project))
    member, reason = resolve_assignee(f, github=gh, now=NOW)
    assert member == team["owner"]
    assert "Slack" in reason and "Projekt-Owner" in reason
