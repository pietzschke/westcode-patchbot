"""Scan status for the header button „Scan & Sync starten“ (spec v2.1 §8.1, review M-9)."""

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from research.models import ScanRun, TargetScan
from testing.factories import make_user_with_member
from triage.models import Job


@pytest.fixture
def client(db):
    user, _ = make_user_with_member(email="dev@westcode.de")
    c = APIClient()
    c.force_login(user)
    return c


def test_status_idle_without_scan(client):
    assert client.get("/api/scans/run/").json() == {"running": False, "job_id": None, "scan_run": None}


def test_status_running_while_job_active_with_progress(client):
    job_id = client.post("/api/scans/run/").json()["job_id"]
    body = client.get("/api/scans/run/").json()
    assert (body["running"], body["job_id"]) == (True, job_id)
    run = ScanRun.objects.create(trigger="MANUAL", started_at=timezone.now())
    for ref in ("westcoder/a", "westcoder/b"):
        TargetScan.objects.create(scan_run=run, target_type="REPO", target_ref=ref, status="OK")
    body = client.get("/api/scans/run/").json()
    assert body["scan_run"]["id"] == run.id
    assert body["scan_run"]["status"] == "RUNNING"
    assert body["scan_run"]["targets_done"] == 2


def test_status_finished_after_job_done(client):
    job_id = client.post("/api/scans/run/").json()["job_id"]
    Job.objects.filter(id=job_id).update(status="DONE", finished_at=timezone.now())
    ScanRun.objects.create(trigger="MANUAL", status="PARTIAL", started_at=timezone.now(), finished_at=timezone.now())
    body = client.get("/api/scans/run/").json()
    assert body["running"] is False
    assert body["scan_run"]["status"] == "PARTIAL"


def test_status_requires_login(db):
    assert APIClient().get("/api/scans/run/").status_code == 403
