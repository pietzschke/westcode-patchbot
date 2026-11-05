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
