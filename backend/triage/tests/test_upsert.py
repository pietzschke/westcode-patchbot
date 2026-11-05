from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from django.db import IntegrityError

from triage.candidates import Candidate, Vuln
from triage.findings import upsert_finding
from triage.models import Finding, FindingEvent
from testing.factories import make_finding, make_project, make_repo

BER = ZoneInfo("Europe/Berlin")
NOW = datetime(2026, 11, 5, 7, 0, tzinfo=BER)  # Thursday


@pytest.fixture
def repo(db):
    return make_repo(full_name="westcoder/materialdatenbank", project=make_project(slug="wuerth"))


def cand(repo, *vulns, package="lodash"):
    return Candidate(
        project=repo.project, layer="APPLICATION", target_ref=f"repo:{repo.full_name}", ecosystem="npm",
        package_name=package, current_version="4.17.15", vulns=list(vulns), repository=repo,
    )


def test_creates_new_untriaged_finding_with_deadline(repo):
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW)
    f = result.finding
    assert result.created
    assert (f.state, f.triage_status, f.complexity) == ("NEW", "UNTRIAGED", "COMPLEX")
    assert f.target_version == "4.17.19"
    assert f.deadline_at == datetime(2026, 11, 6, 7, 0, tzinfo=BER)
    assert FindingEvent.objects.filter(finding=f, to_state="NEW", source="SYSTEM").exists()


def test_same_key_updates_single_finding_and_takes_highest_fix(repo):
    upsert_finding(cand(repo, Vuln("CVE-2026-0001", "MEDIUM", "4.17.19")), now=NOW)
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0002", "HIGH", "4.17.21")), now=NOW)
    f = Finding.objects.get()
    assert result.created is False
    assert sorted(f.vulnerability_ids) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert f.target_version == "4.17.21"
    assert f.highest_severity == "HIGH"


def test_raising_target_in_progress_keeps_deadline(repo):
    f = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW).finding
    f.state = "IN_PROGRESS"
    f.save()
    deadline = f.deadline_at
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0002", "HIGH", "4.17.21")), now=NOW)
    f.refresh_from_db()
    assert result.target_version_raised is True
    assert f.deadline_at == deadline
    assert f.state == "IN_PROGRESS"


def test_dismissed_key_is_muted(repo):
    f = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW).finding
    f.state = "DISMISSED"
    f.save()
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW)
    assert result.muted is True
    assert Finding.objects.count() == 1


def test_new_cve_on_dismissed_key_reopens(repo):
    f = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW).finding
    f.state = "DISMISSED"
    f.save()
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19"), Vuln("CVE-2026-0009", "HIGH", "4.17.21")), now=NOW)
    f.refresh_from_db()
    assert result.finding == f
    assert f.state == "NEW"
    assert f.events.filter(from_state="DISMISSED", to_state="NEW").exists()


@pytest.mark.parametrize("parked", ["SNOOZED", "FILTERED_IRRELEVANT", "SUPPRESSED_UNMONITORED"])
def test_parked_findings_absorb_rescans(repo, parked):
    f = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "MEDIUM", "4.17.19")), now=NOW).finding
    f.state = parked
    f.save()
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0002", "HIGH", "4.17.21")), now=NOW)
    f.refresh_from_db()
    assert result.muted is True
    assert Finding.objects.count() == 1
    assert f.state == parked
    assert f.highest_severity == "HIGH"
    assert sorted(f.vulnerability_ids) == ["CVE-2026-0001", "CVE-2026-0002"]


def test_redetection_after_verified_live_creates_regression(repo):
    f = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW).finding
    f.state = "VERIFIED_LIVE"
    f.save()
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW)
    assert result.created is True
    assert result.finding.regression_of == f


def test_database_prevents_two_open_findings_with_same_key(repo):
    make_finding(project=repo.project, repository=repo, target_ref="repo:x", ecosystem="npm", package_name="lodash")
    with pytest.raises(IntegrityError):
        make_finding(project=repo.project, repository=repo, target_ref="repo:x", ecosystem="npm", package_name="lodash")


def test_factory_supports_related_field_shortcuts(db):
    f = make_finding(repository__deployment_mode="NONE", repository__full_name="westcoder/lib")
    assert (f.repository.full_name, f.repository.deployment_mode) == ("westcoder/lib", "NONE")
    assert f.repository.project == f.project
