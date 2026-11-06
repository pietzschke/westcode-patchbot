"""Read-only sync of the Notion "📂 Projects" database into inventory.Project.

Monitoring precedence (spec v2.1 §4.1):
- new project: monitored iff its status is active;
- status becomes closed/inactive: monitoring is forced off;
- first activation ("Not started" → active): monitoring turns on;
- reactivation after a closed status: unchanged, a human decides;
- a manual toggle in Patchbot persists while the project stays active;
- page no longer returned by Notion: notion_missing + monitoring off.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from inventory.models import Project, TeamMember
from inventory.signals import project_monitoring_changed

logger = logging.getLogger(__name__)

NOTION_API = "https://api.notion.com/v1"
NOTION_VERSION = "2022-06-28"


@dataclass
class NotionSyncResult:
    created: int = 0
    updated: int = 0
    missing: int = 0
    unknown_statuses: list[str] = field(default_factory=list)


def _headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Notion-Version": NOTION_VERSION,
        "Content-Type": "application/json",
    }


def fetch_all_pages(database_id: str, api_key: str, post: Callable[..., Any] = requests.post) -> list[dict]:
    pages: list[dict] = []
    body: dict[str, Any] = {"page_size": 100}
    while True:
        resp = post(f"{NOTION_API}/databases/{database_id}/query", headers=_headers(api_key), json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        pages.extend(data.get("results") or [])
        if not data.get("has_more") or not data.get("next_cursor"):
            return pages
        body = {"page_size": 100, "start_cursor": data["next_cursor"]}


def _title_of(properties: dict) -> str:
    for prop in properties.values():
        if isinstance(prop, dict) and prop.get("type") == "title":
            return "".join(part.get("plain_text", "") for part in prop.get("title") or []).strip()
    return ""


def make_page_title_resolver(api_key: str, get: Callable[..., Any] = requests.get) -> Callable[[str], str | None]:
    cache: dict[str, str | None] = {}

    def resolve(page_id: str) -> str | None:
        if page_id not in cache:
            try:
                resp = get(f"{NOTION_API}/pages/{page_id}", headers=_headers(api_key), timeout=30)
                resp.raise_for_status()
                cache[page_id] = _title_of(resp.json().get("properties") or {})
            except requests.RequestException:
                logger.warning("Could not resolve Notion page title for %s", page_id)
                cache[page_id] = None
        return cache[page_id]

    return resolve


def _prop(properties: dict, key: str) -> dict:
    name = settings.NOTION_PROPERTY_NAMES[key]
    value = properties.get(name)
    return value if isinstance(value, dict) else {}


def _status(properties: dict) -> str:
    prop = _prop(properties, "status")
    inner = prop.get(prop.get("type", "status")) or {}
    return str(inner.get("name") or "").strip()


def _owner(properties: dict) -> TeamMember | None:
    for person in _prop(properties, "owner").get("people") or []:
        email = str((person.get("person") or {}).get("email") or "").strip().lower()
        if email:
            member = TeamMember.objects.filter(email=email).first()
            if member:
                return member
    return None


def _customer(properties: dict, resolve_page_title: Callable[[str], str | None]) -> str:
    for rel in _prop(properties, "client").get("relation") or []:
        if rel.get("id"):
            return resolve_page_title(rel["id"]) or ""
    return ""


def _unique_slug(name: str) -> str:
    base = slugify(name)[:120] or "project"
    slug, n = base, 2
    while Project.objects.filter(slug=slug).exists():
        slug, n = f"{base}-{n}", n + 1
    return slug


def set_monitoring(project: Project, monitored: bool, *, source: str) -> None:
    """Persist a monitoring change and notify listeners (only when the value changes)."""
    if project.is_monitored == monitored:
        return
    project.is_monitored = monitored
    project.save(update_fields=["is_monitored"])
    project_monitoring_changed.send(sender=Project, project=project, monitored=monitored, source=source)


def _default_fetch() -> list[dict]:
    return fetch_all_pages(settings.NOTION_PROJECTS_DATABASE_ID, settings.NOTION_API_KEY)


@transaction.atomic
def sync_notion_projects(
    pages: list[dict] | None = None,
    *,
    fetch_pages: Callable[[], list[dict]] | None = None,
    resolve_page_title: Callable[[str], str | None] | None = None,
    now=None,
) -> NotionSyncResult:
    now = now or timezone.now()
    if pages is None:
        pages = (fetch_pages or _default_fetch)()
    resolve = resolve_page_title or make_page_title_resolver(settings.NOTION_API_KEY)
    active = set(settings.NOTION_ACTIVE_STATUSES)
    not_started = set(settings.NOTION_NOT_STARTED_STATUSES)
    closed = set(settings.NOTION_CLOSED_STATUSES)

    result = NotionSyncResult()
    seen_ids: set[str] = set()
    for page in pages:
        page_id = str(page.get("id") or "")
        if not page_id:
            continue
        seen_ids.add(page_id)
        props = page.get("properties") or {}
        status = _status(props)
        if status not in active | not_started | closed and status not in result.unknown_statuses:
            result.unknown_statuses.append(status)
            logger.warning("Unknown Notion project status %r on page %s; treating as inactive", status, page_id)

        fields = {
            "name": _title_of(props) or "Unbenanntes Projekt",
            "notion_status": status,
            "customer_name": _customer(props, resolve),
            "owner": _owner(props),
            "is_internal": bool(_prop(props, "internal").get("checkbox", False)),
            "notion_missing": False,
            "last_notion_synced_at": now,
        }
        project = Project.objects.filter(notion_page_id=page_id).first()
        if project is None:
            Project.objects.create(
                notion_page_id=page_id, slug=_unique_slug(fields["name"]), is_monitored=status in active, **fields
            )
            result.created += 1
            continue

        previous_status = project.notion_status
        for key, value in fields.items():
            setattr(project, key, value)
        project.save()
        result.updated += 1
        if status in active:
            if previous_status in not_started:
                set_monitoring(project, True, source="NOTION")
        else:
            set_monitoring(project, False, source="NOTION")

    for project in Project.objects.exclude(notion_page_id__isnull=True).exclude(notion_page_id__in=seen_ids):
        if not project.notion_missing:
            project.notion_missing = True
            project.save(update_fields=["notion_missing"])
            result.missing += 1
        set_monitoring(project, False, source="NOTION")
    return result
