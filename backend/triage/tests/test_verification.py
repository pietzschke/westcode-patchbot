from datetime import date, datetime, timedelta, timezone

import pytest

from triage.verification import needs_deployment_decision, verification_rows, verify_findings
from testing.factories import make_container, make_finding, make_host, make_project, make_repo
from testing.fakes import FakeGitHub

MERGED = datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
NOW = MERGED + timedelta(hours=3)
REPO = "westcoder/materialdatenbank"


@pytest.fixture
def setup(db):
    project = make_project(slug="wuerth")
    repo = make_repo(full_name=REPO, project=project, deployment_mode="CONTAINER")
    finding = make_finding(repository=repo, project=project, state="PR_MERGED_WAITING_LIVE",
                           merge_commit_sha="m1", pr_merged_at=MERGED, package_name="lodash",
                           vulnerability_ids=["CVE-2026-0001"])
    return project, repo, finding


def container(project, repo, *, seen=NOW, slug="mdb", **kw):
    host = make_host(slug=slug, project=project, last_seen_at=seen)
    return make_container(host, project=project, repository=repo, **kw)


def no_scan(digest):
    return None


def state(f):
    f.refresh_from_db()
    return f.state


def test_no_linked_container_never_verifies(setup):
    _, _, f = setup
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "PR_MERGED_WAITING_LIVE"


def test_stale_telemetry_never_verifies(setup):
    project, repo, f = setup
    container(project, repo, seen=MERGED - timedelta(minutes=5), oci_revision="r2")
    verify_findings(github=FakeGitHub(compare={(REPO, "m1", "r2"): "ahead"}), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "PR_MERGED_WAITING_LIVE"


def test_revision_proof_verifies(setup):
    project, repo, f = setup
    container(project, repo, oci_revision="r2")
    verified = verify_findings(github=FakeGitHub(compare={(REPO, "m1", "r2"): "ahead"}), image_scan_lookup=no_scan, now=NOW)
    f.refresh_from_db()
    assert verified == [f]
    assert (f.state, f.verified_live_at) == ("VERIFIED_LIVE", NOW)
    assert f.events.filter(to_state="VERIFIED_LIVE", note__icontains="Revision").exists()


def test_build_timestamp_alone_is_not_proof(setup):
    project, repo, f = setup
    container(project, repo, oci_revision="old", image_created_at=MERGED + timedelta(minutes=30))
    verify_findings(github=FakeGitHub(compare={(REPO, "m1", "old"): "behind"}), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "PR_MERGED_WAITING_LIVE"


def test_diverged_revision_is_not_proof(setup):
    project, repo, f = setup
    container(project, repo, oci_revision="branch")
    verify_findings(github=FakeGitHub(compare={(REPO, "m1", "branch"): "diverged"}), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "PR_MERGED_WAITING_LIVE"


def test_every_linked_container_must_be_proven(setup):
    project, repo, f = setup
    container(project, repo, slug="mdb", oci_revision="r2")
    container(project, repo, slug="converter", oci_revision="old")
    gh = FakeGitHub(compare={(REPO, "m1", "r2"): "ahead", (REPO, "m1", "old"): "behind"})
    verify_findings(github=gh, image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "PR_MERGED_WAITING_LIVE"
    rows = {r["host"]: r for r in verification_rows(f, github=gh, image_scan_lookup=no_scan)}
    assert rows["mdb.westcode.de"]["proof"] == "REVISION"
    assert rows["converter.westcode.de"]["proof"] is None


def test_checkout_proof_for_host_checkout_repos(setup):
    project, repo, f = setup
    repo.deployment_mode = "HOST_CHECKOUT"
    repo.save()
    container(project, repo, git_head_sha="m1")
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "VERIFIED_LIVE"


def test_scan_proof_verifies(setup):
    project, repo, f = setup
    container(project, repo, oci_revision="", repo_digests=["ecr/mdb@sha256:new"])
    clean = {"status": "OK", "vulnerabilities": []}
    verify_findings(github=FakeGitHub(), image_scan_lookup=lambda d: clean if d.endswith("new") else None, now=NOW)
    assert state(f) == "VERIFIED_LIVE"


def test_scan_still_showing_the_cve_is_not_proof(setup):
    project, repo, f = setup
    container(project, repo, oci_revision="", repo_digests=["ecr/mdb@sha256:old"])
    dirty = {"status": "OK", "vulnerabilities": [{"id": "CVE-2026-0001", "package": "lodash"}]}
    verify_findings(github=FakeGitHub(), image_scan_lookup=lambda d: dirty, now=NOW)
    assert state(f) == "PR_MERGED_WAITING_LIVE"


def test_unknown_deployment_mode_without_containers_asks_for_decision(setup):
    _, repo, f = setup
    repo.deployment_mode = "UNKNOWN"
    repo.save()
    assert needs_deployment_decision(f) is True


def test_known_deployment_mode_needs_no_decision(setup):
    _, _, f = setup
    assert needs_deployment_decision(f) is False


@pytest.mark.django_db
def test_container_image_finding_verifies_when_all_digests_are_clean():
    project = make_project(slug="wuerth")
    for slug, digest in (("mdb", "ecr/mdb@sha256:a"), ("mdb2", "ecr/mdb@sha256:b")):
        make_container(make_host(slug=slug, project=project, last_seen_at=NOW), project=project, repo_digests=[digest])
    f = make_finding(layer="CONTAINER_IMAGE", project=project, target_ref="image:ecr/mdb", ecosystem="ubuntu",
                     package_name="openssl", vulnerability_ids=["CVE-2026-0100"], state="IN_PROGRESS",
                     discovered_at=NOW - timedelta(days=1))
    scans = {"ecr/mdb@sha256:a": {"status": "OK", "vulnerabilities": []},
             "ecr/mdb@sha256:b": {"status": "OK", "vulnerabilities": [{"id": "CVE-2026-0100", "package": "openssl"}]}}
    verify_findings(github=FakeGitHub(), image_scan_lookup=scans.get, now=NOW)
    assert state(f) == "IN_PROGRESS"
    scans["ecr/mdb@sha256:b"] = {"status": "OK", "vulnerabilities": []}
    verify_findings(github=FakeGitHub(), image_scan_lookup=scans.get, now=NOW)
    assert state(f) == "VERIFIED_LIVE"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "installed,apt_age_h,reboot,start_state,expected",
    [
        ("1.1.1f-1ubuntu2.23", 2, False, "IN_PROGRESS", "VERIFIED_LIVE"),
        ("1.1.1f-1ubuntu2.23", 2, False, "NEW", "VERIFIED_LIVE"),
        ("1.1.1f-1ubuntu2.22", 2, False, "IN_PROGRESS", "IN_PROGRESS"),
        ("1.1.1f-1ubuntu2.23", 30, False, "IN_PROGRESS", "IN_PROGRESS"),
        ("1.1.1f-1ubuntu2.23", 2, True, "IN_PROGRESS", "IN_PROGRESS"),
    ],
)
def test_apt_verification(installed, apt_age_h, reboot, start_state, expected):
    host = make_host(slug="mdb", last_seen_at=NOW, reboot_required=reboot,
                     apt_lists_updated_at=NOW - timedelta(hours=apt_age_h))
    host.packages.create(name="openssl", installed_version=installed, candidate_version="", is_security_update=False)
    f = make_finding(layer="INFRASTRUCTURE", host=host, ecosystem="deb", package_name="openssl",
                     target_version="1.1.1f-1ubuntu2.23", state=start_state, discovered_at=NOW - timedelta(hours=6),
                     acknowledged_at=NOW - timedelta(hours=5))
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == expected


@pytest.mark.django_db
def test_reboot_verification_requires_report_after_acknowledgement():
    host = make_host(slug="mdb", last_seen_at=NOW - timedelta(hours=6), reboot_required=False)
    f = make_finding(layer="INFRASTRUCTURE", host=host, ecosystem="host", package_name="__reboot__",
                     state="IN_PROGRESS", discovered_at=NOW - timedelta(hours=8), acknowledged_at=NOW - timedelta(hours=5))
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "IN_PROGRESS"
    host.last_seen_at = NOW
    host.save()
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "VERIFIED_LIVE"


@pytest.mark.django_db
def test_os_eol_verifies_after_upgrade():
    host = make_host(slug="mdb", last_seen_at=NOW, os_distro="ubuntu", os_version="20.04", os_eol_date=date(2025, 5, 31))
    f = make_finding(layer="INFRASTRUCTURE", host=host, ecosystem="host", package_name="__os_eol__",
                     state="IN_PROGRESS", discovered_at=NOW - timedelta(days=3))
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "IN_PROGRESS"
    host.os_version, host.os_eol_date = "24.04", date(2029, 5, 31)
    host.save()
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "VERIFIED_LIVE"


@pytest.mark.django_db
def test_os_eol_with_unknown_eol_date_does_not_verify():
    # An unknown (distro, version) pair leaves os_eol_date empty — that is no proof of a supported release.
    host = make_host(slug="mdb", last_seen_at=NOW, os_distro="", os_version="", os_eol_date=None)
    f = make_finding(layer="INFRASTRUCTURE", host=host, ecosystem="host", package_name="__os_eol__",
                     state="IN_PROGRESS", discovered_at=NOW - timedelta(days=3))
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "IN_PROGRESS"


@pytest.mark.django_db
def test_waiting_finding_of_undeployed_repo_resolves_without_deployment():
    repo = make_repo(project=make_project(), deployment_mode="NONE")
    f = make_finding(repository=repo, state="PR_MERGED_WAITING_LIVE", merge_commit_sha="m1", pr_merged_at=MERGED)
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    assert state(f) == "RESOLVED_NO_DEPLOYMENT"
