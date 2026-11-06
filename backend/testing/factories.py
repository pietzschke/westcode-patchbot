"""Model factories for tests. Every factory creates sensible unique defaults."""

from __future__ import annotations

import itertools

from django.contrib.auth import get_user_model

from fleet.models import Host, HostContainer
from inventory.models import Project, RepositoryAsset, TeamMember

_seq = itertools.count(1)


def _n() -> int:
    return next(_seq)


def make_member(**kw) -> TeamMember:
    n = _n()
    defaults = {"name": f"Member {n}", "email": f"member{n}@westcode.de"}
    defaults.update(kw)
    return TeamMember.objects.create(**defaults)


def make_user_with_member(**kw):
    member = make_member(**kw)
    user = get_user_model().objects.create_user(username=member.email, email=member.email)
    member.user = user
    member.save(update_fields=["user"])
    return user, member


def make_project(**kw) -> Project:
    n = _n()
    defaults = {"slug": f"project-{n}", "name": f"Project {n}"}
    defaults.update(kw)
    return Project.objects.create(**defaults)


def make_repo(**kw) -> RepositoryAsset:
    n = _n()
    defaults = {"full_name": f"westcoder/repo-{n}"}
    defaults.update(kw)
    return RepositoryAsset.objects.create(**defaults)


def make_host(**kw) -> Host:
    n = _n()
    slug = kw.pop("slug", f"host-{n}")
    defaults = {
        "slug": slug,
        "hostname": f"{slug}.westcode.de",
        "provider": "hetzner",
        "stack_name": f"hetzner-{slug}",
    }
    defaults.update(kw)
    return Host.objects.create(**defaults)


def make_container(host: Host, **kw) -> HostContainer:
    n = _n()
    defaults = {
        "container_id": f"c{n}",
        "name": f"container-{n}",
        "image_tag": f"example/app-{n}:latest",
        "image_id": f"sha256:img{n}",
    }
    defaults.update(kw)
    return HostContainer.objects.create(host=host, **defaults)


def make_finding(**kw):
    """Create a Finding. Supports ``repository__<field>=…`` / ``project__<field>=…`` shortcuts."""
    from datetime import timedelta

    from django.utils import timezone

    from triage.models import Finding

    related: dict[str, dict] = {}
    for key in [k for k in kw if "__" in k]:
        rel, field = key.split("__", 1)
        related.setdefault(rel, {})[field] = kw.pop(key)

    n = _n()
    host = kw.pop("host", None)
    repository = kw.pop("repository", None)
    project = kw.pop("project", None)
    if project is None and "project" in related:
        project = make_project(**related["project"])
    if repository is None and project is None:
        project = make_project()
    if repository is not None and project is None:
        project = repository.project or make_project()
    layer = kw.get("layer", "APPLICATION")
    if repository is None and ("repository" in related or (layer == "APPLICATION" and host is None)):
        repository = make_repo(project=project, **related.get("repository", {}))

    now = timezone.now()
    if repository is not None:
        target_ref = f"repo:{repository.full_name}"
    elif host is not None:
        target_ref = f"host:{host.slug}"
    else:
        target_ref = f"target-{n}"
    defaults = {
        "layer": layer,
        "target_ref": target_ref,
        "ecosystem": "npm",
        "package_name": f"pkg-{n}",
        "current_version": "1.0.0",
        "target_version": "1.0.1",
        "vulnerability_ids": [f"CVE-2026-{9000 + n}"],
        "highest_severity": "HIGH",
        "state": "NEW",
        "complexity": "COMPLEX",
        "discovered_at": now,
        "deadline_at": now + timedelta(days=1),
    }
    defaults.update(kw)
    return Finding.objects.create(project=project, repository=repository, host=host, **defaults)
