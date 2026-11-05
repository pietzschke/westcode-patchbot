from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from fleet.infra_sync import sync_infra_hosts


class Command(BaseCommand):
    help = "Imports the host list from a local westcode-infra checkout (stacks/*/servers.tf)."

    def add_arguments(self, parser):
        parser.add_argument("infra_root", type=Path, help="Path to the westcode-infra checkout.")

    def handle(self, *args, **options):
        infra_root: Path = options["infra_root"]
        if not (infra_root / "stacks").is_dir():
            raise CommandError(f"{infra_root} has no stacks/ directory; not a westcode-infra checkout.")
        hosts = sync_infra_hosts(infra_root)
        self.stdout.write(self.style.SUCCESS(f"Synced {len(hosts)} hosts from {infra_root}."))
