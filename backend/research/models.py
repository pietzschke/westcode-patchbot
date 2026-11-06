from django.db import models


class ScanRun(models.Model):
    STATUSES = [("RUNNING", "Running"), ("OK", "OK"), ("PARTIAL", "Partial"), ("FAILED", "Failed")]

    trigger = models.CharField(max_length=16)  # SCHEDULED | MANUAL
    status = models.CharField(max_length=16, choices=STATUSES, default="RUNNING")
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-started_at", "-id"]

    def __str__(self) -> str:
        return f"ScanRun {self.id} ({self.status})"


class TargetScan(models.Model):
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="targets")
    target_type = models.CharField(max_length=16)  # REPO | IMAGE | HOST
    target_ref = models.CharField(max_length=512)
    status = models.CharField(max_length=16)  # OK | FAILED | SKIPPED
    error = models.TextField(blank=True, default="")
    vulnerability_count = models.IntegerField(default=0)
    duration_ms = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]


class ImageScanCache(models.Model):
    """Latest scan of one running image, keyed by its immutable digest reference (repo@sha256:…)."""

    image_ref = models.CharField(max_length=512, unique=True)
    scanned_at = models.DateTimeField()
    status = models.CharField(max_length=16)
    vulnerabilities = models.JSONField(default=list, blank=True)


class ExploitSignal(models.Model):
    """Exploit likelihood per CVE: listed in CISA KEV and/or FIRST EPSS score."""

    cve_id = models.CharField(max_length=64, primary_key=True)
    kev_listed = models.BooleanField(default=False)
    kev_added_at = models.DateField(null=True, blank=True)
    epss = models.FloatField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)


class TriageAnalysisCache(models.Model):
    """Claude triage results keyed by cluster, target version, commit, prompt version and model."""

    cache_key = models.CharField(max_length=64, unique=True)
    result_json = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class MaintenanceUpdate(models.Model):
    """Open Renovate/Dependabot PR without a known CVE (quiet list, no DMs, no deadlines)."""

    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="maintenance_updates")
    repository = models.ForeignKey("inventory.RepositoryAsset", on_delete=models.CASCADE, related_name="maintenance_updates")
    package_name = models.CharField(max_length=255)
    current_version = models.CharField(max_length=128, blank=True, default="")
    target_version = models.CharField(max_length=128, blank=True, default="")
    update_type = models.CharField(max_length=16, default="UNKNOWN")  # PATCH | MINOR | MAJOR | UNKNOWN
    pr_number = models.IntegerField()
    pr_url = models.URLField(max_length=512, blank=True, default="")
    ci_status = models.CharField(max_length=16, blank=True, default="")
    summary_de = models.TextField(blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["package_name"]
        constraints = [models.UniqueConstraint(fields=["repository", "pr_number"], name="uniq_maintenance_pr")]
