from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from inventory.models import Project, RepositoryAsset, TeamMember
from research.models import MaintenanceUpdate
from triage.models import Finding, Job
from testing.factories import make_container, make_finding, make_host, make_member, make_project, make_repo, make_user_with_member


def client_for(**member_kw):
    user, member = make_user_with_member(**member_kw)
    client = APIClient()
    client.force_login(user)
    return client, member


@pytest.fixture
def member_client(db):
    return client_for(email="dev@westcode.de", slack_user_id="U3")


@pytest.fixture
def admin_client(db):
    return client_for(email="admin@westcode.de", is_admin=True)


@pytest.mark.parametrize("path", ["/api/dashboard/", "/api/team/", "/api/triage-projects/"])
def test_endpoints_require_login(db, path):
    assert APIClient().get(path).status_code == 403


def test_dashboard_buckets(member_client):
    client, member = member_client
    make_finding(state="NEW", complexity="SIMPLE", assignee=member)
    make_finding(state="IN_PROGRESS", complexity="COMPLEX", assignee=member)
    make_finding(state="PR_MERGED_WAITING_LIVE", assignee=member)
    make_finding(state="FILTERED_IRRELEVANT")
    body = client.get("/api/dashboard/").json()
    assert [len(body["buckets"][k]) for k in ("simple", "complex", "waiting_live")] == [1, 1, 1]
    assert len(body["filtered"]) == 1
    assert body["ampel"]["color"] in {"RED", "GREY"}
    item = body["buckets"]["simple"][0]
    assert item["assignee"]["id"] == member.id
    assert {"id", "title", "project", "highest_severity", "deadline_at", "overdue", "pr"} <= set(item)


def test_dashboard_lists_maintenance_updates(member_client):
    client, _ = member_client
    repo = make_repo(project=make_project(slug="wuerth"))
    MaintenanceUpdate.objects.create(project=repo.project, repository=repo, package_name="eslint",
                                     target_version="9.2.0", update_type="MINOR", pr_number=42, pr_url="u")
    assert client.get("/api/dashboard/").json()["maintenance"][0]["package_name"] == "eslint"


def test_finding_detail_includes_events_and_verification(member_client):
    client, _ = member_client
    f = make_finding(state="PR_MERGED_WAITING_LIVE",
                     verification_snapshot=[{"host": "mdb.westcode.de", "proof": "REVISION", "fresh": True}])
    body = client.get(f"/api/findings/{f.id}/").json()
    assert body["verification"][0]["proof"] == "REVISION"
    assert "events" in body and "needs_deployment_decision" in body


def test_acknowledge_uses_session_user_not_body(member_client):
    client, member = member_client
    other = make_member(email="other@westcode.de")
    f = make_finding(state="NEW", assignee=other)
    resp = client.post(f"/api/findings/{f.id}/acknowledge/", {"actor_id": other.id}, format="json")
    assert resp.status_code == 200
    f.refresh_from_db()
    assert (f.state, f.assignee) == ("IN_PROGRESS", member)
    assert resp.json()["state"] == "IN_PROGRESS"


def test_acknowledge_invalid_transition_is_409(member_client):
    client, _ = member_client
    f = make_finding(state="VERIFIED_LIVE")
    assert client.post(f"/api/findings/{f.id}/acknowledge/").status_code == 409


def test_dismiss_validates_reason_and_records_session_actor(member_client, settings):
    settings.SLACK_TEAM_CHANNEL_ID = "C-TEAM"
    client, member = member_client
    f = make_finding(state="NEW", highest_severity="MEDIUM")
    short = client.post(f"/api/findings/{f.id}/dismiss/", {"mode": "DISMISSED", "reason": "kurz"}, format="json")
    assert short.status_code == 400
    resp = client.post(f"/api/findings/{f.id}/dismiss/",
                       {"mode": "DISMISSED", "reason": "Nur im Test-Setup genutzt, nicht deployed.", "dismissed_by": 999},
                       format="json")
    assert resp.status_code == 200
    assert Finding.objects.get(id=f.id).dismissed_by == member


def test_dismiss_ignores_null_snooze_days_for_dismissed_mode(member_client):
    client, _ = member_client
    f = make_finding(state="NEW", highest_severity="MEDIUM")
    resp = client.post(f"/api/findings/{f.id}/dismiss/",
                       {"mode": "DISMISSED", "reason": "Nur im Test-Setup genutzt, nicht deployed.", "snooze_days": None},
                       format="json")
    assert resp.status_code == 200
    assert Finding.objects.get(id=f.id).state == "DISMISSED"


def test_snooze_with_null_snooze_days_uses_default(member_client):
    client, _ = member_client
    f = make_finding(state="NEW", highest_severity="MEDIUM")
    resp = client.post(f"/api/findings/{f.id}/dismiss/",
                       {"mode": "SNOOZED", "reason": "Warten auf das nächste Release.", "snooze_days": None},
                       format="json")
    assert resp.status_code == 200
    f.refresh_from_db()
    assert (f.state, (f.snoozed_until - f.dismissed_at).days) == ("SNOOZED", 14)


def test_reopen_and_extend(member_client):
    client, member = member_client
    f = make_finding(state="DISMISSED")
    assert client.post(f"/api/findings/{f.id}/reopen/", {"note": "Neu bewerten bitte"}, format="json").status_code == 200
    f.refresh_from_db()
    assert f.state == "NEW"
    g = make_finding(state="IN_PROGRESS", assignee=member, deadline_at=timezone.now())
    assert client.post(f"/api/findings/{g.id}/extend/", {"reason": "kurz"}, format="json").status_code == 400
    assert client.post(f"/api/findings/{g.id}/extend/", {"reason": "Warten auf Upstream-Fix 2.4.1"},
                       format="json").status_code == 200


def test_unknown_finding_is_404(member_client):
    client, _ = member_client
    assert client.post("/api/findings/999999/acknowledge/").status_code == 404


def test_projects_and_unassigned_assets(member_client):
    client, _ = member_client
    wuerth = make_project(slug="wuerth", name="Würth")
    make_repo(full_name="westcoder/wuerth-converter", suggested_project=wuerth)
    make_host(slug="lonely")
    body = client.get("/api/triage-projects/").json()
    assert body["projects"][0]["slug"] == "wuerth"
    repos = body["unassigned_assets"]["repositories"]
    assert repos[0]["suggested_project"]["slug"] == "wuerth"
    assert body["unassigned_assets"]["hosts"][0]["name"] == "lonely.westcode.de"


def test_monitoring_toggle_is_admin_only(member_client, admin_client):
    make_project(slug="wuerth")
    client, _ = member_client
    assert client.post("/api/triage-projects/wuerth/monitoring/", {"monitored": False}, format="json").status_code == 403
    admin, _ = admin_client
    assert admin.post("/api/triage-projects/wuerth/monitoring/", {"monitored": False}, format="json").status_code == 200
    assert Project.objects.get(slug="wuerth").is_monitored is False


def test_confirm_and_assign_assets(admin_client):
    admin, _ = admin_client
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/wuerth-converter", suggested_project=wuerth)
    host = make_host(slug="lonely")
    container = make_container(host)
    assert admin.post(f"/api/assets/repository/{repo.id}/confirm-suggestion/").status_code == 200
    assert admin.post(f"/api/assets/host/{host.id}/assign/", {"project_slug": "wuerth"}, format="json").status_code == 200
    assert admin.post(f"/api/assets/container/{container.id}/assign/", {"project_slug": None}, format="json").status_code == 200
    assert admin.post(f"/api/assets/unknown/{host.id}/assign/", {"project_slug": "wuerth"}, format="json").status_code == 404
    repo.refresh_from_db()
    host.refresh_from_db()
    assert (repo.project, host.project) == (wuerth, wuerth)


def test_repository_deployment_mode(admin_client):
    admin, _ = admin_client
    repo = make_repo()
    assert admin.patch(f"/api/repositories/{repo.id}/", {"deployment_mode": "BOGUS"}, format="json").status_code == 400
    assert admin.patch(f"/api/repositories/{repo.id}/", {"deployment_mode": "NONE"}, format="json").status_code == 200
    assert RepositoryAsset.objects.get(id=repo.id).deployment_mode == "NONE"


def test_team_management(member_client, admin_client):
    client, _ = member_client
    admin, _ = admin_client
    assert len(client.get("/api/team/").json()) == 2
    payload = {"name": "Neu", "email": "Neu@westcode.de", "github_username": "neu-gh", "layers": ["application"]}
    assert client.post("/api/team/", payload, format="json").status_code == 403
    assert admin.post("/api/team/", {**payload, "email": "neu@gmail.com"}, format="json").status_code == 400
    created = admin.post("/api/team/", payload, format="json")
    assert created.status_code == 201
    member_id = created.json()["id"]
    assert TeamMember.objects.get(id=member_id).email == "neu@westcode.de"
    assert admin.patch(f"/api/team/{member_id}/", {"layers": ["bogus"]}, format="json").status_code == 400
    assert admin.patch(f"/api/team/{member_id}/", {"is_active": False}, format="json").status_code == 200
    assert admin.post(f"/api/team/{member_id}/test-dm/").status_code == 202


def test_scan_run_conflict_while_running(member_client):
    client, _ = member_client
    assert client.post("/api/scans/run/").status_code == 202
    assert client.post("/api/scans/run/").status_code == 409
    assert Job.objects.get().payload == {"trigger": "MANUAL"}


def test_maintenance_analysis_and_notion_sync_enqueue_jobs(member_client, admin_client):
    client, _ = member_client
    admin, _ = admin_client
    repo = make_repo(project=make_project(slug="wuerth"))
    update = MaintenanceUpdate.objects.create(project=repo.project, repository=repo, package_name="eslint",
                                              target_version="9.2.0", pr_number=42)
    assert client.post(f"/api/maintenance/{update.id}/request-analysis/").status_code == 202
    assert client.post("/api/triage-projects/sync-notion/").status_code == 403
    assert admin.post("/api/triage-projects/sync-notion/").status_code == 202
    assert set(Job.objects.values_list("kind", flat=True)) == {"maintenance_analysis", "notion_sync"}


def test_overdue_flag(member_client):
    client, member = member_client
    make_finding(state="IN_PROGRESS", complexity="SIMPLE", assignee=member, deadline_at=timezone.now() - timedelta(hours=1))
    item = client.get("/api/dashboard/").json()["buckets"]["simple"][0]
    assert item["overdue"] is True
