import uuid
from django.db import models
from catalog.models import GitTarget, ServiceGroup
from fleet.models import AgentJob, Host


class RolloutPlan(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service_group = models.ForeignKey(
        ServiceGroup,
        on_delete=models.CASCADE,
        related_name="rollout_plans",
    )
    status = models.CharField(max_length=32, default="READY")
    block_reason = models.CharField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"RolloutPlan({self.id}, {self.service_group.slug}, {self.status})"


class RolloutStep(models.Model):
    plan = models.ForeignKey(
        RolloutPlan,
        on_delete=models.CASCADE,
        related_name="steps",
    )
    order = models.IntegerField()
    step_type = models.CharField(max_length=32)
    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        default=None,
        related_name="rollout_steps",
    )
    git_target = models.ForeignKey(
        GitTarget,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        default=None,
        related_name="rollout_steps",
    )
    agent_job = models.OneToOneField(
        AgentJob,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        default=None,
        related_name="rollout_step",
    )
    status = models.CharField(max_length=32, default="PENDING")
    working_dir = models.CharField(max_length=512, blank=True, default="")
    compose_service = models.CharField(max_length=255, blank=True, default="")
    target_version = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:
        return f"RolloutStep({self.plan_id}, #{self.order}, {self.step_type}, {self.status})"
