from collections.abc import Callable
from typing import Any
from django.db import transaction
from alerts.router import AlertTransport, notify_rollout_rollback
from catalog.models import ServiceGroup
from fleet.models import AgentJob
from rollouts.models import RolloutPlan, RolloutStep


def _default_github_merger(repo_full_name: str, pr_number: int) -> None:
    return None


def _dispatch_host_step(step: RolloutStep) -> AgentJob:
    if step.host is None:
        raise ValueError(f"RolloutStep {step.id} of type {step.step_type} has no host.")

    if step.step_type == "host_compose":
        action_type = "compose_update"
        payload: dict[str, Any] = {
            "working_dir": step.working_dir,
            "service": step.compose_service,
            "target_image": step.target_version,
            "target_version": step.target_version,
        }
    elif step.step_type == "host_apt":
        action_type = "apt_upgrade"
        payload = {
            "target_version": step.target_version,
        }
    else:
        raise ValueError(f"Unsupported host step_type: {step.step_type}")

    job = AgentJob.objects.create(
        host=step.host,
        action_type=action_type,
        payload=payload,
        status="PENDING",
    )
    step.agent_job = job
    step.status = "RUNNING"
    step.save(update_fields=["agent_job", "status"])
    return job


def create_rollout_plan(service_group: ServiceGroup) -> RolloutPlan:
    with transaction.atomic():
        plan = RolloutPlan.objects.create(
            service_group=service_group,
            status="READY",
            block_reason="",
        )
        block_reasons: list[str] = []
        order = 1

        for gt in service_group.git_targets.all():
            if gt.pr_number is not None:
                RolloutStep.objects.create(
                    plan=plan,
                    order=order,
                    step_type="github_merge",
                    git_target=gt,
                    status="PENDING",
                    target_version=gt.target_version,
                )
                order += 1
                if gt.ci_status != "success":
                    block_reasons.append(
                        f"CI-Status für {gt.repo_full_name} PR #{gt.pr_number} ist '{gt.ci_status or 'pending'}' (erwartet 'success')"
                    )

        for ht in service_group.host_targets.select_related("host").all():
            if ht.target_type == "compose":
                RolloutStep.objects.create(
                    plan=plan,
                    order=order,
                    step_type="host_compose",
                    host=ht.host,
                    status="PENDING",
                    working_dir=ht.working_dir,
                    compose_service=ht.compose_service,
                    target_version=ht.target_version,
                )
                order += 1
                if ht.git_clean is False:
                    block_reasons.append(
                        f"Lokale Git-Änderungen (dirty working tree) auf {ht.host.hostname} ({ht.working_dir})"
                    )
            elif ht.target_type == "apt":
                RolloutStep.objects.create(
                    plan=plan,
                    order=order,
                    step_type="host_apt",
                    host=ht.host,
                    status="PENDING",
                    target_version=ht.target_version,
                )
                order += 1
            # Do NOT create direct VM mutation RolloutSteps for target_type == "ecr_app"
            # (deployed by CircleCI when their github_merge step executes, enforcing No Git Drift).

        if block_reasons:
            plan.status = "BLOCKED"
            plan.block_reason = "; ".join(block_reasons)
            plan.save(update_fields=["status", "block_reason"])

        return plan


def start_rollout_plan(
    plan: RolloutPlan,
    github_merger: Callable[[str, int], Any] | None = None,
) -> RolloutPlan:
    if plan.status != "READY":
        raise ValueError(
            f"Cannot execute RolloutPlan {plan.id}: status is {plan.status} ({plan.block_reason})"
        )

    merger = github_merger or _default_github_merger

    with transaction.atomic():
        plan.status = "RUNNING"
        plan.save(update_fields=["status"])

        git_steps = list(
            plan.steps.filter(step_type="github_merge", status="PENDING")
            .select_related("git_target")
            .order_by("order")
        )
        for step in git_steps:
            if step.git_target and step.git_target.pr_number is not None:
                merger(step.git_target.repo_full_name, step.git_target.pr_number)
            step.status = "SUCCEEDED"
            step.save(update_fields=["status"])

        first_host_step = (
            plan.steps.filter(
                step_type__in=["host_compose", "host_apt"],
                status="PENDING",
            )
            .select_related("host")
            .order_by("order")
            .first()
        )
        if first_host_step is not None:
            _dispatch_host_step(first_host_step)
        else:
            plan.status = "SUCCEEDED"
            plan.save(update_fields=["status"])

        return plan


def advance_rollout_on_job_result(
    job: AgentJob,
    transport: AlertTransport | None = None,
) -> RolloutPlan:
    with transaction.atomic():
        step = (
            RolloutStep.objects.select_related("plan__service_group")
            .filter(agent_job=job)
            .first()
        )
        if step is None:
            raise ValueError(f"AgentJob {job.id} is not associated with any RolloutStep.")

        plan = step.plan

        if job.status == "SUCCEEDED":
            step.status = "SUCCEEDED"
            step.save(update_fields=["status"])

            next_step = (
                plan.steps.filter(
                    step_type__in=["host_compose", "host_apt"],
                    status="PENDING",
                )
                .select_related("host")
                .order_by("order")
                .first()
            )
            if next_step is not None:
                _dispatch_host_step(next_step)
            else:
                plan.status = "SUCCEEDED"
                plan.save(update_fields=["status"])
        elif job.status in {"ROLLED_BACK", "FAILED"}:
            step.status = "ROLLED_BACK"
            step.save(update_fields=["status"])
            plan.steps.filter(status="PENDING").update(status="ABORTED")
            plan.status = "ROLLED_BACK"
            plan.save(update_fields=["status"])
            try:
                notify_rollout_rollback(
                    plan,
                    logs=job.result_logs or "",
                    transport=transport,
                )
            except Exception:
                pass

        return plan
