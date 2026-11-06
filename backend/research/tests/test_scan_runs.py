import pytest

from research.models import TargetScan
from research.scan_runs import finalize_scan_run, record_target, start_scan_run
from research.trivy import TrivyResult


@pytest.mark.django_db
@pytest.mark.parametrize(
    "statuses,expected",
    [(["OK", "OK"], "OK"), (["OK", "FAILED"], "PARTIAL"), (["FAILED", "FAILED"], "FAILED"), ([], "OK")],
)
def test_finalize_derives_run_status(statuses, expected):
    run = start_scan_run("MANUAL")
    assert run.status == "RUNNING"
    for i, status in enumerate(statuses):
        record_target(run, "REPO", f"repo:r{i}", TrivyResult(status=status, error="", vulnerabilities=[]))
    finalize_scan_run(run)
    assert run.status == expected
    assert run.finished_at is not None


@pytest.mark.django_db
def test_record_target_stores_error_and_count():
    run = start_scan_run("SCHEDULED")
    record_target(run, "IMAGE", "image:ecr/mdb", TrivyResult("FAILED", "pull denied", []), duration_ms=1200)
    record_target(run, "REPO", "repo:westcoder/mdb", TrivyResult("OK", "", [{"id": "CVE-1"}, {"id": "CVE-2"}]))
    failed = TargetScan.objects.get(target_type="IMAGE")
    ok = TargetScan.objects.get(target_type="REPO")
    assert (failed.status, failed.error, failed.duration_ms) == ("FAILED", "pull denied", 1200)
    assert ok.vulnerability_count == 2
