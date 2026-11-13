from django.core.management.base import BaseCommand

from controlplane.worker import build_deps
from research.pipeline import run_scan


class Command(BaseCommand):
    help = "Run one full scan pipeline synchronously."

    def handle(self, *args, **options):
        d = build_deps()
        run = run_scan(github=d.github, trivy=d.trivy, llm=d.llm, slack=d.slack, bumper=d.bumper,
                       worktrees=d.worktrees, patcher=d.patcher, trigger="MANUAL", release_checkout=d.release_checkout)
        self.stdout.write(f"Scan run {run.id}: {run.status} {run.error}".strip())
