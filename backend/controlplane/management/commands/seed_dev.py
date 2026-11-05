from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from inventory.models import Project, RepositoryAsset, TeamMember
from triage.models import Finding


class Command(BaseCommand):
    help = "Create demo data for local development. Refuses to run unless DEBUG is on."

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError("seed_dev only runs with DJANGO_DEBUG=true (never in production).")
        now = timezone.now()
        owner, _ = TeamMember.objects.get_or_create(
            email="dev@westcode.de", defaults={"name": "Dev User", "is_admin": True, "slack_user_id": "UDEV"})
        project, _ = Project.objects.get_or_create(slug="demo", defaults={"name": "Demo-Projekt", "owner": owner})
        repo, _ = RepositoryAsset.objects.get_or_create(full_name="westcoder/demo-app",
                                                       defaults={"project": project, "deployment_mode": "CONTAINER"})
        for i, (package, complexity, state) in enumerate([
            ("lodash", "SIMPLE", "NEW"), ("django", "COMPLEX", "IN_PROGRESS"), ("axios", "SIMPLE", "PR_MERGED_WAITING_LIVE"),
        ]):
            Finding.objects.get_or_create(
                project=project, layer="APPLICATION", target_ref=f"repo:{repo.full_name}", ecosystem="npm",
                package_name=package,
                defaults={"repository": repo, "current_version": "1.0.0", "target_version": "1.0.1",
                          "vulnerability_ids": [f"CVE-2026-{9900 + i}"], "highest_severity": "HIGH",
                          "complexity": complexity, "state": state, "assignee": owner, "discovered_at": now,
                          "deadline_at": now + timedelta(days=1), "triage_status": "TRIAGED",
                          "summary_de": "Demo-Finding für die lokale Entwicklung."},
            )
        self.stdout.write(self.style.SUCCESS("Demo data created. Log in with PATCHBOT_DEV_LOGIN=1 as dev@westcode.de."))
