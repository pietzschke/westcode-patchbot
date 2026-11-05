"""Repository discovery and project matching for the asset graph.

Only the container → repository link via the ``org.opencontainers.image.source``
label is deterministic and applied automatically. Everything else is a
*suggestion* that a human confirms in the „Unzugeordnete Assets“ inbox.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from django.db import transaction

from fleet.models import Host, HostContainer
from inventory.models import Project, RepositoryAsset

BOT_CONFIG_FILES = (
    "renovate.json",
    "renovate.json5",
    ".github/renovate.json",
    ".github/renovate.json5",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
)

# Curated aliases (asset key → project slug). Changes go through code review.
PROJECT_ALIASES: dict[str, str] = {
    "materialdatenbank": "wuerth",
    "wuerth-converter": "wuerth",
    "mdb": "wuerth",
    "converter": "wuerth",
}

_OCI_SOURCE_RE = re.compile(r"^https://github\.com/(?P<repo>westcoder/[A-Za-z0-9_.-]+?)(?:\.git)?/?$", re.IGNORECASE)


@transaction.atomic
def sync_repositories(github) -> dict:
    created = updated = 0
    for repo in github.list_org_repos():
        has_bot = (not repo["archived"]) and any(github.file_exists(repo["full_name"], f) for f in BOT_CONFIG_FILES)
        _, was_created = RepositoryAsset.objects.update_or_create(
            full_name=repo["full_name"],
            defaults={
                "default_branch": repo["default_branch"],
                "is_archived": repo["archived"],
                "has_bot_updates": has_bot,
            },
        )
        created += was_created
        updated += not was_created
    return {"created": created, "updated": updated}


def link_containers_to_repositories(containers=None) -> int:
    """Link unlinked containers to their repository via the OCI source label.

    ``containers`` optionally narrows the candidates (e.g. to the rows of one agent report).
    """
    repos = {r.full_name.lower(): r for r in RepositoryAsset.objects.all()}
    linked = 0
    candidates = HostContainer.objects.all() if containers is None else containers
    for container in candidates.filter(repository__isnull=True).exclude(oci_source=""):
        match = _OCI_SOURCE_RE.match(container.oci_source.strip())
        repo = repos.get(match.group("repo").lower()) if match else None
        if repo is None:
            continue
        container.repository = repo
        if container.project_id is None and repo.project_id is not None:
            container.project_id = repo.project_id
        container.save(update_fields=["repository", "project"])
        linked += 1
    return linked


def _keys_for_repo(repo: RepositoryAsset) -> list[str]:
    return [repo.full_name.split("/", 1)[-1].lower()]


def _keys_for_host(host: Host) -> list[str]:
    return [host.slug.lower(), host.hostname.split(".", 1)[0].lower(), host.stack_name.lower().removeprefix("hetzner-")]


def _keys_for_container(container: HostContainer) -> list[str]:
    keys = [container.compose_service.lower()]
    if container.working_dir:
        keys.append(PurePosixPath(container.working_dir).name.lower())
    # Last path segment first, then strip the tag: a registry port ("host:5000/name") also contains ":".
    image_repo = container.image_tag.split("@", 1)[0].rsplit("/", 1)[-1].split(":", 1)[0]
    keys.append(image_repo.lower())
    return [k for k in keys if k]


def _match_project(keys: list[str], projects: dict[str, Project]) -> Project | None:
    for key in keys:
        alias = PROJECT_ALIASES.get(key)
        if alias and alias in projects:
            return projects[alias]
    for key in keys:
        for slug, project in projects.items():
            if key == slug or key.startswith(f"{slug}-"):
                return project
    return None


def suggest_projects() -> int:
    projects = {p.slug: p for p in Project.objects.all()}
    suggested = 0
    for model, keys_for in (
        (RepositoryAsset, _keys_for_repo),
        (Host, _keys_for_host),
        (HostContainer, _keys_for_container),
    ):
        for asset in model.objects.filter(project__isnull=True):
            project = _match_project(keys_for(asset), projects)
            if project is not None and asset.suggested_project_id != project.id:
                asset.suggested_project = project
                asset.save(update_fields=["suggested_project"])
                suggested += 1
    return suggested


def confirm_suggestion(asset) -> None:
    if asset.suggested_project_id is None:
        raise ValueError("Asset has no suggestion to confirm.")
    asset.project_id = asset.suggested_project_id
    asset.suggested_project = None
    asset.save(update_fields=["project", "suggested_project"])
