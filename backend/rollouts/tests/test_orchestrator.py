import hashlib
import pytest
from rest_framework.test import APIClient
from fleet.models import AgentJob, Host, HostContainer
from catalog.correlator import rebuild_service_groups
from catalog.models import GitTarget, HostTarget, ServiceGroup
from rollouts.orchestrator import (
    advance_rollout_on_job_result,
    create_rollout_plan,
    start_rollout_plan,
)


@pytest.fixture
def plausible_group(db):
    sg = ServiceGroup.objects.create(
        slug="plausible",
        display_name="Plausible Analytics",
        logo_key="plausible",
        category="action_required",
        current_version_summary="2.1.0",
        target_version="2.1.2",
        highest_cve_id="CVE-2026-3104",
        highest_severity="HIGH",
    )
    GitTarget.objects.create(
        service_group=sg,
        repo_full_name="westcoder/westcode-web",
        file_path="deploy/compose.yaml",
        pr_number=142,
        pr_url="https://github.com/westcoder/westcode-web/pull/142",
        ci_status="success",
        target_version="2.1.2",
    )
    for slug in ["c2", "wew-homepage", "masteroil"]:
        h = Host.objects.create(
            slug=slug,
            hostname=f"{slug}.westcode.de",
            provider="hetzner",
            stack_name=f"hetzner-{slug}",
        )
        HostTarget.objects.create(
            service_group=sg,
            host=h,
            target_type="compose",
            working_dir="/opt/plausible",
            compose_service="plausible",
            running_version="2.1.0",
            target_version="2.1.2",
            git_clean=True,
        )
    return sg


@pytest.mark.django_db
def test_serial_canary_dispatches_host_1_then_aborts_rest_on_rollback(plausible_group):
    merged_prs = []
    plan = create_rollout_plan(plausible_group)
    assert plan.status == "READY"

    start_rollout_plan(plan, github_merger=lambda repo, pr: merged_prs.append((repo, pr)))
    assert merged_prs == [("westcoder/westcode-web", 142)]

    host_steps = list(plan.steps.filter(step_type="host_compose").order_by("order"))
    assert host_steps[0].status == "RUNNING"
    assert host_steps[0].agent_job is not None
    assert host_steps[1].status == "PENDING"
    assert host_steps[2].status == "PENDING"

    job1 = host_steps[0].agent_job
    job1.status = "ROLLED_BACK"
    job1.result_payload = {"logs": "Healthcheck HTTP 502"}
    job1.save()

    plan = advance_rollout_on_job_result(job1)
    assert plan.status == "ROLLED_BACK"
    for s in host_steps[1:]:
        s.refresh_from_db()
        assert s.status == "ABORTED"
        assert s.agent_job is None


@pytest.mark.django_db
def test_create_rollout_plan_blocks_when_opt_git_is_dirty(plausible_group):
    ht = plausible_group.host_targets.first()
    ht.git_clean = False
    ht.save()

    plan = create_rollout_plan(plausible_group)
    assert plan.status == "BLOCKED"
    assert ht.host.hostname in plan.block_reason


@pytest.mark.django_db
def test_create_rollout_plan_blocks_when_ci_not_success(plausible_group):
    gt = plausible_group.git_targets.first()
    gt.ci_status = "failure"
    gt.save()

    plan = create_rollout_plan(plausible_group)
    assert plan.status == "BLOCKED"
    assert "westcoder/westcode-web" in plan.block_reason


@pytest.mark.django_db
def test_ecr_app_enforces_no_git_drift_without_host_steps(db):
    host = Host.objects.create(
        slug="service",
        hostname="service.westcode.de",
        provider="hetzner",
        stack_name="hetzner-westcode-service",
    )
    HostContainer.objects.create(
        host=host,
        container_id="c-hub",
        name="hub-backend-1",
        image_tag="hub-backend",
        image_id="sha256:111",
        repo_digests=["069962555850.dkr.ecr.eu-central-1.amazonaws.com/westcode-hub@sha256:999"],
        oci_title="westcode-hub",
        oci_revision="8f3a1c40",
        working_dir="/opt/hub",
        compose_service="backend",
        git_clean=False,
        status="running",
    )
    groups = rebuild_service_groups(
        renovate_prs=[
            {
                "service_slug": "westcode-hub",
                "repo_full_name": "westcoder/westcode-hub",
                "file_path": "Dockerfile",
                "pr_number": 88,
                "pr_url": "https://github.com/westcoder/westcode-hub/pull/88",
                "ci_status": "success",
                "target_version": "5.4.2",
            }
        ],
    )
    hub_group = next(g for g in groups if g.slug == "westcode-hub")
    ht = hub_group.host_targets.first()
    assert ht.target_type == "ecr_app"

    plan = create_rollout_plan(hub_group)
    assert plan.status == "READY"
    steps = list(plan.steps.order_by("order"))
    assert len(steps) == 1
    assert steps[0].step_type == "github_merge"

    merged = []
    start_rollout_plan(plan, github_merger=lambda repo, pr: merged.append((repo, pr)))
    assert merged == [("westcoder/westcode-hub", 88)]
    plan.refresh_from_db()
    assert plan.status == "SUCCEEDED"


@pytest.mark.django_db
def test_serial_canary_advances_via_agent_job_result_api_and_rest_endpoints(plausible_group):
    # Set agent tokens on the three hosts
    tokens = {}
    for host in Host.objects.all():
        raw_tok = f"tok-{host.slug}"
        tokens[host.id] = raw_tok
        host.agent_token_hash = hashlib.sha256(raw_tok.encode()).hexdigest()
        host.save()

    client = APIClient()

    # 1. GET /api/services/
    services_resp = client.get("/api/services/")
    assert services_resp.status_code == 200
    services_data = services_resp.json()
    assert len(services_data) == 1
    assert services_data[0]["slug"] == "plausible"
    assert len(services_data[0]["git_targets"]) == 1
    assert len(services_data[0]["host_targets"]) == 3
    assert "hostname" in services_data[0]["host_targets"][0]

    # 2. GET /api/hosts/
    hosts_resp = client.get("/api/hosts/")
    assert hosts_resp.status_code == 200
    assert len(hosts_resp.json()) == 3

    # 3. POST /api/services/plausible/plan/
    plan_resp = client.post("/api/services/plausible/plan/")
    assert plan_resp.status_code in (200, 201)
    plan_data = plan_resp.json()
    plan_id = plan_data["id"]
    assert plan_data["status"] == "READY"
    assert len(plan_data["steps"]) == 4

    # 4. POST /api/plans/<plan_id>/execute/
    exec_resp = client.post(f"/api/plans/{plan_id}/execute/")
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "RUNNING"

    # Step through each of the 3 host_compose steps via AgentJobResultView
    for idx in range(3):
        running_job = AgentJob.objects.filter(status="PENDING").first()
        assert running_job is not None
        host_tok = tokens[running_job.host_id]
        agent_client = APIClient()
        agent_client.credentials(HTTP_AUTHORIZATION=f"Bearer {host_tok}")
        res_resp = agent_client.post(
            f"/api/agent/jobs/{running_job.id}/result/",
            data={"status": "SUCCEEDED", "result_payload": {"logs": f"host {idx} ok"}},
            format="json",
        )
        assert res_resp.status_code == 200

    from rollouts.models import RolloutPlan

    final_plan = RolloutPlan.objects.get(id=plan_id)
    assert final_plan.status == "SUCCEEDED"
    assert all(s.status == "SUCCEEDED" for s in final_plan.steps.all())


@pytest.mark.django_db
def test_apt_rollout_plan_creates_host_apt_steps_and_aborts_on_failed(db):
    sg = ServiceGroup.objects.create(
        slug="ubuntu-apt",
        display_name="Ubuntu / Debian apt",
        logo_key="ubuntu",
        category="action_required",
        current_version_summary="2 Hosts",
        target_version="dist-upgrade",
        highest_severity="HIGH",
    )
    for slug in ["linklama", "masteroil"]:
        h = Host.objects.create(
            slug=slug,
            hostname=f"{slug}.westcode.de",
            provider="hetzner",
            stack_name=f"hetzner-{slug}",
        )
        HostTarget.objects.create(
            service_group=sg,
            host=h,
            target_type="apt",
            running_version="ubuntu 24.04",
            target_version="3 Pakete",
        )

    plan = create_rollout_plan(sg)
    assert plan.status == "READY"
    steps = list(plan.steps.order_by("order"))
    assert len(steps) == 2
    assert all(s.step_type == "host_apt" for s in steps)

    start_rollout_plan(plan)
    steps[0].refresh_from_db()
    steps[1].refresh_from_db()
    assert steps[0].status == "RUNNING"
    assert steps[0].agent_job.action_type == "apt_upgrade"
    assert steps[1].status == "PENDING"

    job1 = steps[0].agent_job
    job1.status = "FAILED"
    job1.save()
    advance_rollout_on_job_result(job1)

    plan.refresh_from_db()
    steps[0].refresh_from_db()
    steps[1].refresh_from_db()
    assert plan.status == "ROLLED_BACK"
    assert steps[0].status == "ROLLED_BACK"
    assert steps[1].status == "ABORTED"

