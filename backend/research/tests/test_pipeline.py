from datetime import datetime, timezone

import pytest

from research.pipeline import run_scan
from research.trivy import TrivyResult
from triage.models import Finding
from testing.factories import make_member, make_project, make_repo
from testing.fakes import FakeGitHub, FakeLLM, FakeSlack

NOW = datetime(2026, 11, 9, 6, 0, tzinfo=timezone.utc)
VULN = {"id": "CVE-2026-0001", "package": "lodash", "installed": "4.17.15", "fixed": "4.17.21", "severity": "HIGH",
        "ecosystem": "npm", "pkg_class": "lang-pkgs", "target": "package-lock.json"}
TRIAGE = {"reachability": "REACHABLE", "reachability_reason_category": "OTHER", "complexity": "SIMPLE",
          "confidence": 0.9, "summary_de": "Erreichbar.", "breaking_changes_de": "", "affected_files": []}


class Trivy:
    def __init__(self, result=None):
        self.result = result or TrivyResult("OK", "", [VULN])

    def scan_repo(self, full_name, path):
        return self.result

    def scan_image(self, ref):
        return TrivyResult("OK", "", [])


class Bumper:
    def bump(self, *args):
        return ["package.json", "package-lock.json"]


class Worktrees:
    def create(self, repo, base, branch):
        return f"/tmp/{branch}"

    def commit_all(self, path, message):
        return True

    def release(self, path):
        pass


def no_epss(ids):
    return {"data": []}


def scan(**overrides):
    kwargs = dict(github=overrides.pop("github"), trivy=overrides.pop("trivy", Trivy()),
                  llm=FakeLLM(output=TRIAGE), slack=overrides.pop("slack"), bumper=Bumper(), worktrees=Worktrees(),
                  epss_fetch=no_epss, now=NOW)
    kwargs.update(overrides)
    return run_scan(**kwargs)


@pytest.mark.django_db
def test_end_to_end_scan_is_idempotent():
    owner = make_member(email="owner@westcode.de", slack_user_id="UO")
    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth", owner=owner))
    gh = FakeGitHub(repos=[{"full_name": "westcoder/mdb", "default_branch": "main", "archived": False}])
    slack = FakeSlack()

    first = scan(github=gh, slack=slack)
    second = scan(github=gh, slack=slack)

    f = Finding.objects.get()
    assert (first.status, second.status) == ("OK", "OK")
    assert (f.state, f.complexity, f.triage_status, f.assignee, f.pr_source) == ("NEW", "SIMPLE", "TRIAGED", owner, "PATCHBOT")
    assert len(gh.created_pulls) == 1
    assert [m[0] for m in slack.messages] == ["UO"]


@pytest.mark.django_db
def test_failed_repo_scan_makes_run_partial_and_sends_nothing():
    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    make_repo(full_name="westcoder/ok", project=make_project(slug="ses"))

    class MixedTrivy(Trivy):
        def scan_repo(self, full_name, path):
            return TrivyResult("FAILED", "db error", []) if full_name == "westcoder/mdb" else TrivyResult("OK", "", [])

    slack = FakeSlack()
    run = scan(github=FakeGitHub(), trivy=MixedTrivy(), slack=slack)
    assert run.status == "PARTIAL"
    assert slack.messages == []


@pytest.mark.django_db
def test_unexpected_error_marks_run_failed():
    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))

    class ExplodingGitHub(FakeGitHub):
        def list_org_repos(self):
            raise RuntimeError("GitHub down")

    run = scan(github=ExplodingGitHub(), slack=FakeSlack())
    assert run.status == "FAILED"
    assert "GitHub down" in run.error


@pytest.mark.django_db
def test_checkouts_are_released():
    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    released = []
    scan(github=FakeGitHub(), slack=FakeSlack(), release_checkout=released.append)
    assert len(released) == 1


@pytest.mark.django_db
def test_clean_github_steps_mark_github_integration_healthy():
    from triage.models import IntegrationHealth
    from triage.notifications import record_health

    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    record_health("github", False, "push rejected", NOW)

    run = scan(github=FakeGitHub(), slack=FakeSlack())

    assert run.status == "OK"
    health = IntegrationHealth.objects.get(name="github")
    assert (health.ok, health.last_error) == (True, "")


@pytest.mark.django_db
def test_failed_pr_handling_keeps_github_integration_failing():
    from triage.models import IntegrationHealth
    from triage.notifications import record_health

    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    record_health("github", True, "", NOW)

    class PushFailingGitHub(FakeGitHub):
        def push_branch(self, repo, branch, worktree):
            raise RuntimeError("push rejected")

    scan(github=PushFailingGitHub(), slack=FakeSlack())

    health = IntegrationHealth.objects.get(name="github")
    assert health.ok is False
    assert "push rejected" in health.last_error


@pytest.mark.django_db
def test_failed_repo_sync_marks_github_integration_failing():
    from triage.models import IntegrationHealth

    class ExplodingGitHub(FakeGitHub):
        def list_org_repos(self):
            raise RuntimeError("GitHub down")

    scan(github=ExplodingGitHub(), slack=FakeSlack())

    health = IntegrationHealth.objects.get(name="github")
    assert health.ok is False
    assert "GitHub down" in health.last_error


@pytest.mark.django_db
def test_rescan_lifts_filter_when_cve_becomes_kev_listed():
    from research.models import ExploitSignal
    from testing.factories import make_finding

    repo = make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    filtered = make_finding(repository=repo, state="FILTERED_IRRELEVANT", ecosystem="npm", package_name="lodash",
                            vulnerability_ids=["CVE-2026-0001"], target_version="4.17.21", triage_status="TRIAGED")
    ExploitSignal.objects.create(cve_id="CVE-2026-0001", kev_listed=True)

    # No Claude (llm=None): the deterministic reopen rule alone must lift the filter.
    scan(github=FakeGitHub(), slack=FakeSlack(), llm=None)

    filtered.refresh_from_db()
    assert filtered.kev_listed is True
    assert filtered.state == "NEW"
    assert filtered.events.filter(from_state="FILTERED_IRRELEVANT", to_state="NEW").exists()


@pytest.mark.django_db
def test_raised_target_on_acknowledged_finding_retriages_supersedes_pr_and_notifies_once():
    from triage.lifecycle import acknowledge

    owner = make_member(email="owner@westcode.de", slack_user_id="UO")
    dev = make_member(email="dev@westcode.de", slack_user_id="UD")
    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth", owner=owner))
    gh = FakeGitHub(repos=[{"full_name": "westcoder/mdb", "default_branch": "main", "archived": False}])
    slack = FakeSlack()
    scan(github=gh, slack=slack)
    f = Finding.objects.get()
    acknowledge(f, dev, source="WEB", now=NOW)
    first_pr = f.pr_number

    newer = {**VULN, "id": "CVE-2026-0002", "fixed": "4.17.23"}
    raised_trivy = Trivy(TrivyResult("OK", "", [VULN, newer]))
    scan(github=gh, slack=slack, trivy=raised_trivy)
    scan(github=gh, slack=slack, trivy=raised_trivy)

    f.refresh_from_db()
    assert (f.state, f.target_version, f.triage_status, f.assignee) == ("IN_PROGRESS", "4.17.23", "TRIAGED", dev)
    assert f.pr_number != first_pr and f.pr_target_version == "4.17.23"
    assert len(gh.created_pulls) == 2
    assert [m[0] for m in slack.messages] == ["UO", "UD"]


@pytest.mark.django_db
def test_new_cves_get_epss_before_triage():
    from research.models import ExploitSignal

    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    known = {**VULN, "id": "CVE-2026-0003", "package": "axios"}
    ExploitSignal.objects.create(cve_id="CVE-2026-0003", epss=0.01)
    requested = []

    def fetch(ids):
        requested.extend(ids)
        return {"data": [{"cve": "CVE-2026-0001", "epss": "0.42"}]}

    scan(github=FakeGitHub(), slack=FakeSlack(), trivy=Trivy(TrivyResult("OK", "", [VULN, known])), epss_fetch=fetch)

    assert requested == ["CVE-2026-0001"]  # only CVEs without a stored EPSS score
    assert Finding.objects.get(package_name="lodash").max_epss == pytest.approx(0.42)


@pytest.mark.django_db
def test_epss_outage_does_not_fail_the_scan():
    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))

    def fetch(ids):
        raise ConnectionError("api.first.org unreachable")

    run = scan(github=FakeGitHub(), slack=FakeSlack(), epss_fetch=fetch)
    assert run.status == "OK"
    assert Finding.objects.get().state == "NEW"
