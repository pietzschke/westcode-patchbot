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
