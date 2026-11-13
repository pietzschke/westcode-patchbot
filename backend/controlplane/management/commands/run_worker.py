import time

from django.core.management.base import BaseCommand

from controlplane.worker import build_deps, tick


class Command(BaseCommand):
    help = "Run the Patchbot worker loop (scheduler, webhooks, jobs)."

    def add_arguments(self, parser):
        parser.add_argument("--interval", type=int, default=30, help="Seconds between ticks.")
        parser.add_argument("--once", action="store_true", help="Run a single tick and exit.")

    def handle(self, *args, **options):
        deps = build_deps()
        while True:
            tick(deps)
            if options["once"]:
                return
            time.sleep(options["interval"])
