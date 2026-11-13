"""Quiet „Wartungs-Updates“: Renovate/Dependabot PRs without a known CVE (spec v2.1 §5.6).

No Slack DMs, no deadlines. A human can request a Claude changelog analysis,
which is posted once as a PR comment (updated in place).
"""

from __future__ import annotations

import anthropic
from django.conf import settings
from django.db import transaction

from inventory.models import RepositoryAsset
from research.bot_prs import parse_bot_pr
from research.models import MaintenanceUpdate
from triage.models import OPEN_STATES, PARKED_STATES, Finding
from triage.versions import compare_versions

MAINTENANCE_MARKER = "<!-- patchbot:maintenance -->"


def _update_type(current: str, target: str) -> str:
    target_parts = target.lstrip("vV").split(".")
    if not current:
        return "MAJOR" if len(target_parts) == 1 else "UNKNOWN"
    current_parts = current.lstrip("vV").split(".")
    if current_parts[0] != target_parts[0]:
        return "MAJOR"
    if len(current_parts) > 1 and len(target_parts) > 1 and current_parts[1] != target_parts[1]:
        return "MINOR"
    return "PATCH" if compare_versions("npm", target, current) > 0 else "UNKNOWN"


@transaction.atomic
def sync_maintenance_updates(*, github) -> dict:
    created = removed = 0
    for repo in RepositoryAsset.objects.filter(project__is_monitored=True, is_archived=False).select_related("project"):
        security_packages = {
            name.lower()
            for name in Finding.objects.filter(repository=repo, state__in=OPEN_STATES + PARKED_STATES)
            .values_list("package_name", flat=True)
        }
        security_prs = set(
            Finding.objects.filter(repository=repo, pr_number__isnull=False).values_list("pr_number", flat=True)
        )
        seen: set[int] = set()
        for pull in github.list_open_pulls(repo.full_name):
            bot = parse_bot_pr(pull)
            if bot is None or bot.number in security_prs or bot.package.lower() in security_packages:
                continue
            seen.add(bot.number)
            _, was_created = MaintenanceUpdate.objects.update_or_create(
                repository=repo,
                pr_number=bot.number,
                defaults={
                    "project": repo.project,
                    "package_name": bot.package,
                    "current_version": bot.from_version,
                    "target_version": bot.version,
                    "update_type": _update_type(bot.from_version, bot.version),
                    "pr_url": bot.html_url,
                    "ci_status": github.combined_ci_status(repo.full_name, bot.head_ref) if bot.head_ref else "",
                },
            )
            created += was_created
        stale = MaintenanceUpdate.objects.filter(repository=repo).exclude(pr_number__in=seen)
        removed += stale.count()
        stale.delete()
    return {"created": created, "removed": removed}


def request_analysis(update: MaintenanceUpdate, *, github, client) -> MaintenanceUpdate:
    prompt = (
        "Fasse auf Deutsch in höchstens 6 Sätzen zusammen, ob dieses Abhängigkeits-Update für das Projekt "
        "Breaking Changes oder Risiken mit sich bringt und worauf beim Review zu achten ist.\n\n"
        f"<untrusted_update>\nPaket: {update.package_name}\nVon: {update.current_version or 'unbekannt'}\n"
        f"Auf: {update.target_version}\nArt: {update.update_type}\n</untrusted_update>"
    )
    try:
        response = client.messages.create(
            model=settings.PATCHBOT_CLAUDE_MODEL,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as exc:
        raise RuntimeError(f"Claude-Analyse fehlgeschlagen: {exc}") from exc
    if response.stop_reason == "refusal":
        raise RuntimeError("Claude hat die Analyse abgelehnt.")
    text = next((b.text for b in response.content if getattr(b, "type", "") == "text"), "").strip()
    update.summary_de = text
    update.save(update_fields=["summary_de", "updated_at"])
    github.upsert_marker_comment(update.repository.full_name, update.pr_number, MAINTENANCE_MARKER,
                                 f"**Westcode Patchbot – Update-Analyse**\n\n{text}\n\n_KI-Einschätzung, kein Ersatz für ein Review._")
    return update
