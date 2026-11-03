from django.core.management.base import BaseCommand
from catalog.live_sync import run_live_sync


class Command(BaseCommand):
    help = "Runs live synchronization against westcode-infra, GitHub PRs (via gh), and local repositories (via trivy)."

    def handle(self, *args, **options):
        summary = run_live_sync()
        self.stdout.write(
            self.style.SUCCESS(
                f"Live sync complete: {summary['hosts_count']} hosts, "
                f"{summary['services_count']} service groups, "
                f"{summary['prs_count']} GitHub PRs, "
                f"{summary['vulns_count']} actionable CVEs."
            )
        )
