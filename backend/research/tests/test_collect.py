from datetime import date, datetime, timedelta, timezone

import pytest

from research.collect import collect_and_upsert
from research.models import ImageScanCache, TargetScan
from research.scan_runs import start_scan_run
from research.trivy import TrivyResult
from triage.models import Finding
from testing.factories import make_container, make_finding, make_host, make_project, make_repo
from testing.fakes import FakeGitHub

NOW = datetime(2026, 11, 5, 6, 0, tzinfo=timezone.utc)
LODASH = {"id": "CVE-2026-0001", "package": "lodash", "installed": "4.17.15", "fixed": "4.17.21",
          "severity": "HIGH", "ecosystem": "npm", "pkg_class": "lang-pkgs", "target": "package-lock.json"}
OPENSSL = {"id": "CVE-2026-0100", "package": "openssl", "installed": "3.0.13-0ubuntu3.4", "fixed": "3.0.13-0ubuntu3.5",
           "severity": "HIGH", "ecosystem": "ubuntu", "pkg_class": "os-pkgs", "target": "ubuntu 24.04"}


class FakeTrivy:
    def __init__(self, fs=None, image=None):
        self.fs = fs or {}
        self.image = image or {}
        self.fs_calls, self.image_calls = [], []

    def scan_repo(self, full_name, path):
        self.fs_calls.append(full_name)
        return self.fs.get(full_name, TrivyResult("OK", "", []))

    def scan_image(self, ref):
        self.image_calls.append(ref)
        return self.image.get(ref, TrivyResult("OK", "", []))


def run_collect(github=None, trivy=None):
    run = start_scan_run("MANUAL", now=NOW)
    result = collect_and_upsert(run, github=github or FakeGitHub(), trivy=trivy or FakeTrivy(), now=NOW)
    return run, result


@pytest.mark.django_db
def test_only_monitored_and_active_repositories_are_scanned():
    make_repo(full_name="westcoder/active", project=make_project(slug="a", is_monitored=True))
    make_repo(full_name="westcoder/unmonitored", project=make_project(slug="b", is_monitored=False))
    make_repo(full_name="westcoder/archived", project=make_project(slug="c"), is_archived=True)
    make_repo(full_name="westcoder/unassigned")
    trivy = FakeTrivy()
    run_collect(trivy=trivy)
    assert trivy.fs_calls == ["westcoder/active"]


@pytest.mark.django_db
def test_repo_vulnerabilities_become_application_findings():
    repo = make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    second = {**LODASH, "id": "CVE-2026-0002", "fixed": "4.17.20", "target": "frontend/package-lock.json"}
    _, result = run_collect(trivy=FakeTrivy(fs={"westcoder/mdb": TrivyResult("OK", "", [LODASH, second])}))
    f = Finding.objects.get()
    assert (f.layer, f.target_ref, f.repository, f.ecosystem, f.package_name) == (
        "APPLICATION", "repo:westcoder/mdb", repo, "npm", "lodash",
    )
    assert sorted(f.vulnerability_ids) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert f.target_version == "4.17.21"
    assert result.created == 1
    repo.refresh_from_db()
    assert repo.last_scanned_at == NOW


@pytest.mark.django_db
def test_checkout_failure_is_a_failed_target():
    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))

    class BrokenGitHub(FakeGitHub):
        def checkout(self, repo):
            raise RuntimeError("clone failed")

    run, _ = run_collect(github=BrokenGitHub())
    target = TargetScan.objects.get(scan_run=run, target_type="REPO")
    assert (target.status, target.error) == ("FAILED", "clone failed")


@pytest.mark.django_db
def test_failed_target_keeps_existing_findings():
    repo = make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    existing = make_finding(repository=repo, project=repo.project, state="NEW", package_name="lodash")
    run, _ = run_collect(trivy=FakeTrivy(fs={"westcoder/mdb": TrivyResult("FAILED", "db error", [])}))
    existing.refresh_from_db()
    assert existing.state == "NEW"
    assert TargetScan.objects.get(scan_run=run, target_type="REPO").status == "FAILED"


@pytest.mark.django_db
def test_fix_on_default_branch_moves_finding_to_live_verification():
    repo = make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"), deployment_mode="CONTAINER")
    existing = make_finding(repository=repo, project=repo.project, state="IN_PROGRESS", package_name="lodash")
    run_collect(github=FakeGitHub(head_shas={"westcoder/mdb": "c0ffee"}))
    existing.refresh_from_db()
    assert existing.state == "PR_MERGED_WAITING_LIVE"
    assert existing.merge_commit_sha == "c0ffee"


@pytest.mark.django_db
def test_same_digest_is_scanned_once_and_lang_pkgs_go_to_application_layer():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/mdb", project=wuerth)
    for slug in ("mdb", "mdb2"):
        make_container(make_host(slug=slug, project=wuerth, last_seen_at=NOW), project=wuerth, repository=repo,
                       repo_digests=["ecr/materialdatenbank@sha256:d1"])
    trivy = FakeTrivy(
        fs={"westcoder/mdb": TrivyResult("OK", "", [LODASH])},
        image={"ecr/materialdatenbank@sha256:d1": TrivyResult("OK", "", [LODASH, OPENSSL])},
    )
    run_collect(trivy=trivy)
    assert trivy.image_calls == ["ecr/materialdatenbank@sha256:d1"]
    assert sorted(Finding.objects.values_list("layer", "package_name", "target_ref")) == [
        ("APPLICATION", "lodash", "repo:westcoder/mdb"),
        ("CONTAINER_IMAGE", "openssl", "image:ecr/materialdatenbank"),
    ]


@pytest.mark.django_db
def test_third_party_image_lang_packages_are_container_findings():
    wuerth = make_project(slug="wuerth")
    make_container(make_host(slug="mdb", project=wuerth, last_seen_at=NOW), project=wuerth,
                   repo_digests=["docker.io/library/node@sha256:n1"])
    run_collect(trivy=FakeTrivy(image={"docker.io/library/node@sha256:n1": TrivyResult("OK", "", [LODASH])}))
    assert Finding.objects.get().layer == "CONTAINER_IMAGE"


@pytest.mark.django_db
def test_recent_image_scan_is_reused():
    wuerth = make_project(slug="wuerth")
    make_container(make_host(slug="mdb", project=wuerth, last_seen_at=NOW), project=wuerth,
                   repo_digests=["ecr/mdb@sha256:d1"])
    ImageScanCache.objects.create(image_ref="ecr/mdb@sha256:d1", scanned_at=NOW - timedelta(hours=3),
                                  status="OK", vulnerabilities=[OPENSSL])
    trivy = FakeTrivy()
    run_collect(trivy=trivy)
    assert trivy.image_calls == []
    assert Finding.objects.get().package_name == "openssl"


@pytest.mark.django_db
def test_host_layer_candidates():
    host = make_host(slug="mdb", project=make_project(slug="wuerth"), reboot_required=True, last_seen_at=NOW,
                     os_distro="ubuntu", os_version="20.04", os_eol_date=date(2025, 5, 31))
    host.packages.create(name="openssl", installed_version="1.1.1f-1ubuntu2.22",
                         candidate_version="1.1.1f-1ubuntu2.23", is_security_update=True, source_pocket="focal-security")
    host.packages.create(name="curl", installed_version="7.68.0-1ubuntu2.24",
                         candidate_version="7.68.0-1ubuntu2.25", is_security_update=False)
    run_collect()
    infra = Finding.objects.filter(layer="INFRASTRUCTURE")
    assert sorted(infra.values_list("package_name", flat=True)) == ["__os_eol__", "__reboot__", "openssl"]
    openssl = infra.get(package_name="openssl")
    assert (openssl.host, openssl.ecosystem, openssl.target_version) == (host, "deb", "1.1.1f-1ubuntu2.23")


@pytest.mark.django_db
def test_stale_host_is_a_failed_target_without_new_findings():
    host = make_host(slug="mdb", project=make_project(slug="wuerth"), reboot_required=True,
                     last_seen_at=NOW - timedelta(hours=30))
    run, _ = run_collect()
    assert TargetScan.objects.get(scan_run=run, target_type="HOST").status == "FAILED"
    assert not Finding.objects.filter(host=host).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("relation,expected", [("ahead", "IN_PROGRESS"), ("identical", "IN_PROGRESS"),
                                               ("behind", "PR_MERGED_WAITING_LIVE")])
def test_cve_still_present_after_merge_reopens_waiting_finding(relation, expected):
    repo = make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    f = make_finding(repository=repo, state="PR_MERGED_WAITING_LIVE", ecosystem="npm", package_name="lodash",
                     vulnerability_ids=["CVE-2026-0001"], target_version="4.17.21", merge_commit_sha="m1",
                     pr_merged_at=NOW - timedelta(hours=2), acknowledged_at=NOW - timedelta(hours=3), pr_number=7)
    head = "m1" if relation == "identical" else "h2"
    gh = FakeGitHub(head_shas={"westcoder/mdb": head}, compare={("westcoder/mdb", "m1", "h2"): relation})
    _, result = run_collect(github=gh, trivy=FakeTrivy(fs={"westcoder/mdb": TrivyResult("OK", "", [LODASH])}))
    f.refresh_from_db()
    assert f.state == expected
    if expected == "IN_PROGRESS":
        assert (f.merge_commit_sha, f.pr_number, f.triage_status) == ("", None, "UNTRIAGED")
        assert [x.state for x in result.findings] == ["IN_PROGRESS"]
