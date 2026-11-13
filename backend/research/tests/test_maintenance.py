import pytest

from research.maintenance import MAINTENANCE_MARKER, request_analysis, sync_maintenance_updates
from research.models import MaintenanceUpdate
from testing.factories import make_finding, make_project, make_repo
from testing.fakes import FakeGitHub, FakeLLM

REPO = "westcoder/materialdatenbank"


def bot_pr(number, title, login="renovate[bot]"):
    return {"number": number, "html_url": f"https://github.com/{REPO}/pull/{number}", "user_login": login,
            "head_ref": f"renovate/{number}", "title": title, "draft": False}


@pytest.mark.django_db
def test_non_cve_bot_prs_become_maintenance_updates():
    repo = make_repo(full_name=REPO, project=make_project(slug="wuerth"))
    make_finding(repository=repo, project=repo.project, package_name="lodash", pr_number=41, state="NEW")
    gh = FakeGitHub(pulls={REPO: [
        bot_pr(41, "Update dependency lodash to v4.17.21"),
        bot_pr(42, "Update dependency eslint to v9.2.0"),
        bot_pr(43, "Update dependency typescript to v6"),
        bot_pr(44, "Bump django from 5.2.1 to 5.2.8", login="dependabot[bot]"),
        {**bot_pr(45, "Add feature"), "user_login": "moritz"},
    ]})
    result = sync_maintenance_updates(github=gh)
    updates = {u.package_name: u for u in MaintenanceUpdate.objects.all()}
    assert set(updates) == {"eslint", "typescript", "django"}
    assert updates["typescript"].update_type == "MAJOR"
    assert (updates["django"].update_type, updates["django"].current_version) == ("PATCH", "5.2.1")
    assert updates["eslint"].project == repo.project
    assert result == {"created": 3, "removed": 0}


@pytest.mark.django_db
def test_closed_bot_prs_are_removed_and_unmonitored_projects_ignored():
    make_repo(full_name=REPO, project=make_project(slug="wuerth"))
    make_repo(full_name="westcoder/old", project=make_project(slug="old", is_monitored=False))
    gh = FakeGitHub(pulls={REPO: [bot_pr(42, "Update dependency eslint to v9.2.0")],
                           "westcoder/old": [bot_pr(1, "Update dependency x to v2.0.0")]})
    sync_maintenance_updates(github=gh)
    assert MaintenanceUpdate.objects.count() == 1
    assert sync_maintenance_updates(github=FakeGitHub(pulls={REPO: []})) == {"created": 0, "removed": 1}
    assert MaintenanceUpdate.objects.count() == 0


@pytest.mark.django_db
def test_request_analysis_posts_single_comment():
    repo = make_repo(full_name=REPO, project=make_project(slug="wuerth"))
    update = MaintenanceUpdate.objects.create(project=repo.project, repository=repo, package_name="typescript",
                                              target_version="6", update_type="MAJOR", pr_number=43, pr_url="u")
    gh = FakeGitHub()

    class TextLLM(FakeLLM):
        def __init__(self):
            super().__init__(output={})
            self._response.content[1].text = "Keine Breaking Changes für dieses Projekt erkennbar."

    llm = TextLLM()
    request_analysis(update, github=gh, client=llm)
    request_analysis(update, github=gh, client=llm)
    update.refresh_from_db()
    assert update.summary_de.startswith("Keine Breaking Changes")
    comments = gh.comments[(REPO, 43)]
    assert len(comments) == 1 and MAINTENANCE_MARKER in comments[0]
    assert "<untrusted_" in llm.calls[0]["messages"][0]["content"]
