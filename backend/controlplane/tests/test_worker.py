from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from django.core.management import CommandError, call_command

from controlplane.worker import Deps, process_jobs, recover_stale_jobs, schedule_due_jobs
from triage.jobs import enqueue
from triage.models import Job, ScheduleState
from testing.factories import make_member
from testing.fakes import FakeGitHub, FakeSlack

BER = ZoneInfo("Europe/Berlin")
NOW = datetime(2026, 11, 9, 7, 0, tzinfo=BER)


def deps(**handlers):
    return Deps(github=FakeGitHub(), slack=FakeSlack(), llm=None, trivy=None, bumper=None, worktrees=None,
                patcher=None, handlers=handlers)


@pytest.mark.django_db
def test_schedule_enqueues_due_jobs_once():
    assert "daily_scan" in schedule_due_jobs(now=NOW)
    assert schedule_due_jobs(now=NOW + timedelta(minutes=1)) == []
    assert Job.objects.filter(kind="daily_scan").count() == 1
    assert ScheduleState.objects.get(kind="daily_scan").last_run_at == NOW


@pytest.mark.django_db
def test_jobs_run_through_handlers_and_finish():
    seen = []
    enqueue("grace_eval")
    assert process_jobs(deps(grace_eval=lambda job, d, now: seen.append(job.kind)), now=NOW) == 1
    assert seen == ["grace_eval"]
    assert Job.objects.get().status == "DONE"


@pytest.mark.django_db
def test_failing_job_is_retried_then_failed():
    enqueue("pr_reconcile")

    def boom(job, d, now):
        raise RuntimeError("GitHub 502")

    d = deps(pr_reconcile=boom)
    process_jobs(d, now=NOW)
    job = Job.objects.get()
    assert (job.status, job.attempts) == ("QUEUED", 1)
    assert "GitHub 502" in job.last_error
    process_jobs(d, now=NOW + timedelta(minutes=10))
    process_jobs(d, now=NOW + timedelta(minutes=30))
    assert Job.objects.get().status == "FAILED"


@pytest.mark.django_db
def test_jobs_wait_for_run_after():
    enqueue("grace_eval", run_after=NOW + timedelta(minutes=5))
    assert process_jobs(deps(grace_eval=lambda *a: None), now=NOW) == 0


@pytest.mark.django_db
def test_stale_running_jobs_are_recovered():
    job = enqueue("daily_scan")
    Job.objects.filter(id=job.id).update(status="RUNNING", locked_at=NOW - timedelta(hours=3))
    assert recover_stale_jobs(now=NOW) == 1
    assert Job.objects.get().status == "QUEUED"


@pytest.mark.django_db
def test_test_dm_handler_posts_to_member():
    member = make_member(email="a@westcode.de", slack_user_id="UA")
    enqueue("test_dm", {"member_id": member.id})
    d = deps()
    process_jobs(d, now=NOW)
    assert d.slack.messages[0][0] == "UA"


@pytest.mark.django_db
def test_seed_dev_refuses_without_debug(settings):
    settings.DEBUG = False
    with pytest.raises(CommandError):
        call_command("seed_dev")
