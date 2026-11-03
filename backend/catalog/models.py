from django.db import models
from fleet.models import Host


class ServiceGroup(models.Model):
    slug = models.CharField(max_length=128, unique=True)
    display_name = models.CharField(max_length=255)
    logo_key = models.CharField(max_length=64, blank=True, default="")
    category = models.CharField(max_length=64, default="ready_to_rollout")
    current_version_summary = models.CharField(max_length=255, blank=True, default="")
    target_version = models.CharField(max_length=128, blank=True, default="")
    highest_cve_id = models.CharField(max_length=64, blank=True, default="")
    highest_severity = models.CharField(max_length=32, blank=True, default="")
    summary_line = models.CharField(max_length=512, blank=True, default="")

    class Meta:
        ordering = ["slug"]

    def __str__(self) -> str:
        return f"{self.display_name} ({self.slug})"


class GitTarget(models.Model):
    service_group = models.ForeignKey(
        ServiceGroup,
        on_delete=models.CASCADE,
        related_name="git_targets",
    )
    repo_full_name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=512, blank=True, default="")
    pr_number = models.IntegerField(null=True, blank=True, default=None)
    pr_url = models.CharField(max_length=512, blank=True, default="")
    ci_status = models.CharField(max_length=64, blank=True, default="")
    target_version = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        ordering = ["repo_full_name", "file_path"]

    def __str__(self) -> str:
        return f"{self.repo_full_name}:{self.file_path} (PR #{self.pr_number})"


class HostTarget(models.Model):
    service_group = models.ForeignKey(
        ServiceGroup,
        on_delete=models.CASCADE,
        related_name="host_targets",
    )
    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name="service_targets",
    )
    target_type = models.CharField(max_length=32, default="compose")
    working_dir = models.CharField(max_length=512, blank=True, default="")
    compose_service = models.CharField(max_length=255, blank=True, default="")
    running_version = models.CharField(max_length=128, blank=True, default="")
    target_version = models.CharField(max_length=128, blank=True, default="")
    git_clean = models.BooleanField(null=True, blank=True, default=None)

    class Meta:
        ordering = ["host__hostname", "working_dir"]

    def __str__(self) -> str:
        return f"{self.host.hostname}:{self.service_group.slug} ({self.running_version} -> {self.target_version})"


class VulnerabilityFinding(models.Model):
    service_group = models.ForeignKey(
        ServiceGroup,
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
    )
    vulnerability_id = models.CharField(max_length=64)
    severity = models.CharField(max_length=32)
    status = models.CharField(max_length=64, default="fixed")
    fixed_version = models.CharField(max_length=128, blank=True, default="")
    title = models.CharField(max_length=512, blank=True, default="")
    package_name = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["vulnerability_id"]

    def __str__(self) -> str:
        return f"{self.vulnerability_id} ({self.severity}) on {self.service_group.slug}"
