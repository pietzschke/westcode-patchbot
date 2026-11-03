from django.db import models


class AlertFingerprint(models.Model):
    fingerprint = models.CharField(max_length=255, unique=True)
    channel = models.CharField(max_length=64)
    external_ref = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.fingerprint} ({self.channel}: {self.external_ref})"
