from django.db import models
from django.db.models import Q

LAYERS = [
    ("APPLICATION", "Application dependency"),
    ("CONTAINER_IMAGE", "Container image"),
    ("INFRASTRUCTURE", "Host / OS"),
]
STATES = [
    ("NEW", "Neu"),
    ("IN_PROGRESS", "In Bearbeitung"),
    ("PR_MERGED_WAITING_LIVE", "Gemergt – wartet auf Live-Gang"),
    ("VERIFIED_LIVE", "Live verifiziert"),
    ("RESOLVED_NO_DEPLOYMENT", "Gemergt – kein Deployment"),
    ("SNOOZED", "Zurückgestellt"),
    ("DISMISSED", "Nicht betroffen"),
    ("FILTERED_IRRELEVANT", "Automatisch gefiltert"),
    ("SUPPRESSED_UNMONITORED", "Projekt nicht überwacht"),
]
OPEN_STATES = ("NEW", "IN_PROGRESS", "PR_MERGED_WAITING_LIVE")
PARKED_STATES = ("SNOOZED", "DISMISSED", "FILTERED_IRRELEVANT", "SUPPRESSED_UNMONITORED")
TERMINAL_STATES = ("VERIFIED_LIVE", "RESOLVED_NO_DEPLOYMENT")
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class Finding(models.Model):
    # --- identity & context ---
    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="findings")
    layer = models.CharField(max_length=20, choices=LAYERS)
    target_ref = models.CharField(max_length=255)
    repository = models.ForeignKey(
        "inventory.RepositoryAsset", null=True, blank=True, on_delete=models.SET_NULL, related_name="findings"
    )
    host = models.ForeignKey("fleet.Host", null=True, blank=True, on_delete=models.SET_NULL, related_name="findings")
    image_ref = models.CharField(max_length=512, blank=True, default="")
    ecosystem = models.CharField(max_length=32)
    package_name = models.CharField(max_length=255)
    current_version = models.CharField(max_length=128, blank=True, default="")
    target_version = models.CharField(max_length=128, blank=True, default="")
    vulnerability_ids = models.JSONField(default=list, blank=True)
    highest_severity = models.CharField(max_length=16, default="MEDIUM")
    kev_listed = models.BooleanField(default=False)
    max_epss = models.FloatField(default=0.0)
    regression_of = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="regressions")

    # --- triage ---
    triage_status = models.CharField(max_length=16, default="UNTRIAGED")
    reachability = models.CharField(max_length=32, blank=True, default="")
    complexity = models.CharField(max_length=16, default="COMPLEX")
    confidence = models.FloatField(null=True, blank=True)
    summary_de = models.TextField(blank=True, default="")
    breaking_changes_de = models.TextField(blank=True, default="")
    affected_files = models.JSONField(default=list, blank=True)
    analysis_prompt_version = models.CharField(max_length=64, blank=True, default="")

    # --- pull request ---
    pr_number = models.IntegerField(null=True, blank=True)
    pr_url = models.URLField(max_length=512, blank=True, default="")
    pr_is_draft = models.BooleanField(default=False)
    pr_source = models.CharField(max_length=16, blank=True, default="")
    pr_target_version = models.CharField(max_length=128, blank=True, default="")  # version the linked PR bumps to
    pr_head_ref = models.CharField(max_length=255, blank=True, default="")  # PR branch, for CI status lookups
    ci_status = models.CharField(max_length=16, blank=True, default="")
    merge_commit_sha = models.CharField(max_length=64, blank=True, default="")
    pr_merged_at = models.DateTimeField(null=True, blank=True)

    # --- lifecycle ---
    state = models.CharField(max_length=32, choices=STATES, default="NEW")
    assignee = models.ForeignKey(
        "inventory.TeamMember", null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_findings"
    )
    assigned_reason_de = models.CharField(max_length=255, blank=True, default="")
    discovered_at = models.DateTimeField()
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    verified_live_at = models.DateTimeField(null=True, blank=True)
    deadline_at = models.DateTimeField(null=True, blank=True)
    extended_in_stage = models.CharField(max_length=32, blank=True, default="")
    escalated_stage = models.IntegerField(default=0)
    dismissal_mode = models.CharField(max_length=16, blank=True, default="")
    dismissal_reason = models.TextField(blank=True, default="")
    dismissed_by = models.ForeignKey(
        "inventory.TeamMember", null=True, blank=True, on_delete=models.SET_NULL, related_name="dismissed_findings"
    )
    dismissed_at = models.DateTimeField(null=True, blank=True)
    dismissed_severity = models.CharField(max_length=16, blank=True, default="")
    dismissed_kev_listed = models.BooleanField(default=False)
    snoozed_until = models.DateTimeField(null=True, blank=True)
    manual_runbook = models.TextField(blank=True, default="")
    verification_snapshot = models.JSONField(default=list, blank=True)
    verification_checked_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-discovered_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "layer", "target_ref", "ecosystem", "package_name"],
                condition=Q(state__in=OPEN_STATES),
                name="uniq_open_finding_per_key",
            )
        ]
        indexes = [models.Index(fields=["state"]), models.Index(fields=["deadline_at"])]

    def __str__(self) -> str:
        return f"{self.package_name} {self.target_version} ({self.layer}, {self.state})"

    @property
    def is_open(self) -> bool:
        return self.state in OPEN_STATES


class FindingEvent(models.Model):
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="events")
    at = models.DateTimeField()
    actor = models.ForeignKey("inventory.TeamMember", null=True, blank=True, on_delete=models.SET_NULL)
    source = models.CharField(max_length=16)  # SYSTEM | WEB | SLACK | GITHUB | NOTION
    from_state = models.CharField(max_length=32, blank=True, default="")
    to_state = models.CharField(max_length=32, blank=True, default="")
    note = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["at", "id"]

    def __str__(self) -> str:
        return f"{self.finding_id}: {self.from_state or '∅'} → {self.to_state} ({self.source})"


class NotificationLog(models.Model):
    """Every Slack message sent for a finding; the unique key makes sending idempotent."""

    finding = models.ForeignKey(Finding, null=True, blank=True, on_delete=models.CASCADE, related_name="notifications")
    kind = models.CharField(max_length=32)  # NEW_DM | ESCALATION | TRANSPARENCY
    stage = models.IntegerField(default=0)
    recipient = models.CharField(max_length=64)
    slack_ts = models.CharField(max_length=64, blank=True, default="")
    sent_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["finding", "kind", "stage", "recipient"], name="uniq_notification")
        ]


class IntegrationHealth(models.Model):
    name = models.CharField(max_length=32, primary_key=True)  # slack | github | notion | anthropic
    ok = models.BooleanField(default=True)
    last_error = models.TextField(blank=True, default="")
    checked_at = models.DateTimeField()


class WebhookEvent(models.Model):
    """Signature-verified webhook delivery, processed asynchronously by the worker."""

    source = models.CharField(max_length=16)  # SLACK | GITHUB
    delivery_id = models.CharField(max_length=128, unique=True, null=True, blank=True)
    event_type = models.CharField(max_length=64, blank=True, default="")
    payload = models.JSONField(default=dict)
    received_at = models.DateTimeField()
    status = models.CharField(max_length=16, default="PENDING")  # PENDING | PROCESSED | REJECTED | FAILED
    error = models.TextField(blank=True, default="")
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["received_at", "id"]


class Job(models.Model):
    """DB-backed job queue processed by the worker (scans, syncs, analyses)."""

    kind = models.CharField(max_length=32)
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, default="QUEUED")  # QUEUED | RUNNING | DONE | FAILED
    run_after = models.DateTimeField()
    locked_at = models.DateTimeField(null=True, blank=True)
    attempts = models.IntegerField(default=0)
    last_error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["run_after", "id"]
        indexes = [models.Index(fields=["status", "run_after"])]


class ScheduleState(models.Model):
    kind = models.CharField(max_length=32, primary_key=True)
    last_run_at = models.DateTimeField()
