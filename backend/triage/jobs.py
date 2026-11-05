"""Enqueue/claim helpers for the DB-backed job queue (worker in Task 25)."""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from triage.models import Job

ACTIVE = ("QUEUED", "RUNNING")


def enqueue(kind: str, payload: dict | None = None, *, unique: bool = False, run_after=None) -> Job | None:
    """Queue a job; with unique=True returns None while a job of this kind is queued or running."""
    with transaction.atomic():
        if unique and Job.objects.select_for_update().filter(kind=kind, status__in=ACTIVE).exists():
            return None
        return Job.objects.create(kind=kind, payload=payload or {}, run_after=run_after or timezone.now())
