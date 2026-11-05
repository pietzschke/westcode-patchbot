import importlib.util
import pytest
from django.urls import Resolver404, resolve


def _module_exists(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except ModuleNotFoundError:
        return False


@pytest.mark.parametrize(
    "path",
    [
        "/api/agent/jobs/next/",
        "/api/agent/jobs/00000000-0000-0000-0000-000000000000/result/",
        "/api/plans/",
        "/api/plans/00000000-0000-0000-0000-000000000000/",
        "/api/plans/00000000-0000-0000-0000-000000000000/execute/",
        "/api/services/plausible/plan/",
    ],
)
def test_v1_mutation_endpoints_are_gone(path):
    with pytest.raises(Resolver404):
        resolve(path)


def test_v1_mutation_modules_are_gone():
    assert not _module_exists("rollouts.orchestrator")
    assert not _module_exists("alerts.router")


@pytest.mark.django_db
def test_live_sync_never_fabricates_containers(tmp_path):
    from catalog.live_sync import WESTCODE_SERVICE_DEPLOYMENTS, run_live_sync
    from fleet.models import Host, HostContainer

    slug = WESTCODE_SERVICE_DEPLOYMENTS[0]["hosts"][0]
    Host.objects.create(slug=slug, hostname=f"{slug}.westcode.de", provider="hetzner", stack_name=f"hetzner-{slug}")

    run_live_sync(projects_root=tmp_path, run_trivy=False, run_gh=False)

    assert HostContainer.objects.count() == 0
