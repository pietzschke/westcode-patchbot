"""Notion sync against the real "📂 Projects" schema (Name, Status, Project Manager, Client, Intern)."""

import pytest

from inventory.models import Project
from inventory.notion_sync import fetch_all_pages, set_monitoring, sync_notion_projects
from inventory.signals import project_monitoring_changed
from testing.factories import make_member

CLIENTS = {"client-wuerth": "Adolf Würth GmbH", "client-ses": "SES Sandmann"}


def page(page_id, name, status, *, manager_email=None, client_id="client-wuerth", internal=False):
    return {
        "id": page_id,
        "properties": {
            "Name": {"type": "title", "title": [{"plain_text": name}]},
            "Status": {"type": "status", "status": {"name": status}},
            "Project Manager": {
                "type": "people",
                "people": [{"object": "user", "person": {"email": manager_email}}] if manager_email else [],
            },
            "Client": {"type": "relation", "relation": [{"id": client_id}] if client_id else []},
            "Intern": {"type": "checkbox", "checkbox": internal},
        },
    }


def sync(pages):
    return sync_notion_projects(pages, resolve_page_title=CLIENTS.get)


@pytest.mark.django_db
def test_new_projects_are_monitored_only_when_active():
    owner = make_member(email="lead@westcode.de")
    result = sync([
        page("p1", "Würth", "In progress", manager_email="Lead@westcode.de"),
        page("p2", "Altkunde", "Done"),
        page("p3", "SES Sandmann", "In maintenance", client_id="client-ses"),
        page("p4", "Neues Projekt", "Not started"),
    ])
    assert result.created == 4
    wuerth = Project.objects.get(notion_page_id="p1")
    assert (wuerth.is_monitored, wuerth.owner, wuerth.slug, wuerth.customer_name) == (
        True, owner, "wurth", "Adolf Würth GmbH",
    )
    assert Project.objects.get(notion_page_id="p2").is_monitored is False
    assert Project.objects.get(notion_page_id="p3").is_monitored is True
    assert Project.objects.get(notion_page_id="p4").is_monitored is False


@pytest.mark.django_db
def test_internal_flag_and_missing_client():
    sync([page("p1", "Westcode Service", "In progress", client_id=None, internal=True)])
    project = Project.objects.get(notion_page_id="p1")
    assert project.is_internal is True
    assert project.customer_name == ""


@pytest.mark.django_db
def test_unknown_status_is_treated_as_inactive_and_reported():
    result = sync([page("p1", "Würth", "Pausiert")])
    assert Project.objects.get(notion_page_id="p1").is_monitored is False
    assert result.unknown_statuses == ["Pausiert"]


@pytest.mark.django_db
def test_first_activation_turns_monitoring_on():
    sync([page("p1", "Neues Projekt", "Not started")])
    sync([page("p1", "Neues Projekt", "In progress")])
    assert Project.objects.get(notion_page_id="p1").is_monitored is True


@pytest.mark.django_db
def test_manual_toggle_survives_sync_while_active():
    sync([page("p1", "Würth", "In progress")])
    set_monitoring(Project.objects.get(notion_page_id="p1"), False, source="WEB")
    sync([page("p1", "Würth", "In maintenance")])
    assert Project.objects.get(notion_page_id="p1").is_monitored is False


@pytest.mark.django_db
@pytest.mark.parametrize("closed_status", ["Done", "GESPERRT!"])
def test_closed_in_notion_forces_monitoring_off(closed_status):
    sync([page("p1", "Würth", "In progress")])
    sync([page("p1", "Würth", closed_status)])
    assert Project.objects.get(notion_page_id="p1").is_monitored is False


@pytest.mark.django_db
def test_reactivation_after_done_does_not_turn_monitoring_on():
    sync([page("p1", "Würth", "Done")])
    sync([page("p1", "Würth", "In progress")])
    assert Project.objects.get(notion_page_id="p1").is_monitored is False


@pytest.mark.django_db
def test_page_missing_from_notion_marks_project():
    sync([page("p1", "Würth", "In progress"), page("p2", "SES Sandmann", "In progress")])
    result = sync([page("p2", "SES Sandmann", "In progress")])
    p1 = Project.objects.get(notion_page_id="p1")
    assert result.missing == 1
    assert p1.notion_missing is True
    assert p1.is_monitored is False


@pytest.mark.django_db
def test_slug_is_stable_and_unique():
    sync([page("p1", "Würth", "In progress"), page("p2", "Würth", "In progress")])
    assert sorted(Project.objects.values_list("slug", flat=True)) == ["wurth", "wurth-2"]
    sync([page("p1", "Würth Konzern", "In progress"), page("p2", "Würth", "In progress")])
    assert Project.objects.get(notion_page_id="p1").slug == "wurth"


@pytest.mark.django_db
def test_monitoring_signal_fires_only_on_change():
    received = []

    def handler(sender, project, monitored, **kwargs):
        received.append(monitored)

    project_monitoring_changed.connect(handler)
    try:
        sync([page("p1", "Würth", "In progress")])
        project = Project.objects.get(notion_page_id="p1")
        set_monitoring(project, True, source="WEB")
        set_monitoring(project, False, source="WEB")
    finally:
        project_monitoring_changed.disconnect(handler)
    assert received == [False]


def test_fetch_all_pages_follows_cursor_and_sends_notion_version():
    calls = []

    class Resp:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self.payload

    def post(url, headers=None, json=None, timeout=None):
        calls.append((url, headers, json))
        if not json.get("start_cursor"):
            return Resp({"results": [{"id": "a"}], "has_more": True, "next_cursor": "cur-2"})
        return Resp({"results": [{"id": "b"}], "has_more": False, "next_cursor": None})

    pages = fetch_all_pages("db-1", "secret", post=post)

    assert [p["id"] for p in pages] == ["a", "b"]
    assert calls[0][0] == "https://api.notion.com/v1/databases/db-1/query"
    assert calls[0][1]["Notion-Version"] == "2022-06-28"
    assert calls[0][1]["Authorization"] == "Bearer secret"
    assert calls[1][2]["start_cursor"] == "cur-2"
