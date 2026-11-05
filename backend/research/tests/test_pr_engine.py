import pytest

from research.bumper import BumpFailed
from research.pr_engine import TRIAGE_MARKER, ensure_pr
from testing.factories import make_finding
from testing.fakes import FakeGitHub

REPO = "westcoder/materialdatenbank"


class FakeBumper:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def bump(self, worktree, ecosystem, package, version):
        self.calls.append((ecosystem, package, version))
        if self.fail:
            raise BumpFailed("ERESOLVE could not resolve")
        return ["package.json", "package-lock.json"]


class FakeWorktrees:
    def __init__(self, has_changes=True):
        self.has_changes = has_changes
        self.created, self.commits, self.released = [], [], []

    def create(self, repo, base, branch):
        self.created.append((repo, base, branch))
        return f"/tmp/wt/{branch}"

    def commit_all(self, path, message):
        self.commits.append((path, message))
        return self.has_changes

    def release(self, path):
        self.released.append(path)


def finding(**kw):
    defaults = dict(layer="APPLICATION", complexity="SIMPLE", triage_status="TRIAGED", ecosystem="npm",
                    package_name="lodash", target_version="4.17.21", repository__full_name=REPO,
                    summary_de="lodash.template wird genutzt.", vulnerability_ids=["CVE-2026-0001"])
    defaults.update(kw)
    return make_finding(**defaults)


def bot_pull(number, title, login="renovate[bot]"):
    return {"number": number, "html_url": f"https://github.com/{REPO}/pull/{number}", "user_login": login,
            "head_ref": f"renovate/{number}", "title": title, "draft": False}


@pytest.mark.django_db
def test_reuses_bot_pr_and_upserts_single_comment():
    gh = FakeGitHub(pulls={REPO: [bot_pull(41, "Update dependency lodash to v4.17.21")]})
    f = finding()
    ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees())
    outcome = ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees())
    assert outcome.action == "EXISTING"
    assert (f.pr_number, f.pr_source, f.pr_url) == (41, "BOT", f"https://github.com/{REPO}/pull/41")
    comments = gh.comments[(REPO, 41)]
    assert len(comments) == 1 and TRIAGE_MARKER in comments[0] and "CVE-2026-0001" in comments[0]
    assert gh.pushes == [] and gh.created_pulls == []


@pytest.mark.django_db
def test_dependabot_pr_is_reused_too():
    gh = FakeGitHub(pulls={REPO: [bot_pull(7, "Bump lodash from 4.17.15 to 4.17.21", login="dependabot[bot]")]})
    f = finding()
    assert ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees()).action == "BOT_REUSED"


@pytest.mark.django_db
def test_bot_pr_with_insufficient_version_is_not_reused():
    gh = FakeGitHub(pulls={REPO: [bot_pull(40, "Update dependency lodash to v4.17.19")]})
    f = finding()
    ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees())
    assert f.pr_number != 40
    assert f.pr_source == "PATCHBOT"


@pytest.mark.django_db
def test_simple_without_bot_pr_creates_ready_pr_on_patchbot_branch():
    gh = FakeGitHub()
    bumper, worktrees = FakeBumper(), FakeWorktrees()
    f = finding()
    outcome = ensure_pr(f, github=gh, bumper=bumper, worktrees=worktrees)
    pr = gh.created_pulls[0]
    assert outcome.action == "PR_CREATED"
    assert (pr["head"], pr["base"], pr["draft"]) == ("patchbot/lodash-4.17.21", "main", False)
    assert "patchbot:ai-generated" not in pr["labels"]
    assert "CVE-2026-0001" in pr["body"]
    assert (f.pr_source, f.pr_number, f.pr_is_draft) == ("PATCHBOT", pr["number"], False)
    assert bumper.calls == [("npm", "lodash", "4.17.21")]
    assert gh.pushes == [(REPO, "patchbot/lodash-4.17.21")]
    assert worktrees.released == ["/tmp/wt/patchbot/lodash-4.17.21"]
    assert f.events.filter(note__icontains="PR").exists()


@pytest.mark.django_db
def test_scoped_package_branch_name_is_sanitised():
    gh = FakeGitHub()
    f = finding(package_name="@angular/core", target_version="22.2.1")
    ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees())
    assert gh.created_pulls[0]["head"] == "patchbot/angular-core-22.2.1"


@pytest.mark.django_db
def test_bump_failure_reclassifies_complex_without_pr():
    gh = FakeGitHub()
    worktrees = FakeWorktrees()
    f = finding()
    outcome = ensure_pr(f, github=gh, bumper=FakeBumper(fail=True), worktrees=worktrees)
    assert outcome.action == "BUMP_FAILED"
    assert (f.complexity, f.pr_number) == ("COMPLEX", None)
    assert gh.created_pulls == [] and gh.pushes == []
    assert worktrees.released  # worktree cleaned up on failure


@pytest.mark.django_db
def test_bump_without_changes_creates_no_pr():
    gh = FakeGitHub()
    outcome = ensure_pr(finding(), github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees(has_changes=False))
    assert outcome.action == "SKIPPED"
    assert gh.created_pulls == []


@pytest.mark.django_db
def test_existing_open_patchbot_pr_is_not_duplicated():
    gh = FakeGitHub(pull_details={(REPO, 77): {"state": "open", "merged": False}})
    f = finding(pr_number=77, pr_source="PATCHBOT")
    assert ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees()).action == "EXISTING"
    assert gh.created_pulls == []


@pytest.mark.django_db
def test_closed_unmerged_pr_is_replaced():
    gh = FakeGitHub(pull_details={(REPO, 77): {"state": "closed", "merged": False}})
    f = finding(pr_number=77, pr_source="PATCHBOT")
    assert ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees()).action == "PR_CREATED"
    assert f.pr_number != 77


@pytest.mark.django_db
@pytest.mark.parametrize(
    "kw",
    [{"layer": "INFRASTRUCTURE"}, {"state": "PR_MERGED_WAITING_LIVE"}, {"state": "DISMISSED"}],
)
def test_non_actionable_findings_are_skipped(kw):
    gh = FakeGitHub()
    f = finding(**kw)
    assert ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees()).action == "SKIPPED"
    assert gh.created_pulls == []


@pytest.mark.django_db
def test_complex_without_sandbox_is_left_for_humans():
    gh = FakeGitHub()
    f = finding(complexity="COMPLEX")
    assert ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees()).action == "SKIPPED"
    assert gh.created_pulls == []
