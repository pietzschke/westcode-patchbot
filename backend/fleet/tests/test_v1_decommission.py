import importlib.util
from io import StringIO

import pytest
from django.core.management import call_command
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


@pytest.mark.parametrize("module", ["rollouts", "alerts", "catalog", "catalog.live_sync"])
def test_v1_mutation_modules_are_gone(module):
    assert not _module_exists(module)


@pytest.mark.django_db
def test_infra_host_import_never_fabricates_containers(tmp_path):
    from fleet.models import Host, HostContainer

    stack = tmp_path / "stacks" / "hetzner-mdb"
    stack.mkdir(parents=True)
    (stack / "servers.tf").write_text(
        'resource "hcloud_server" "mdb" {\n  name  = "mdb.westcode.de"\n  image = "ubuntu-24.04"\n}\n'
    )

    call_command("sync_infra_hosts", str(tmp_path), stdout=StringIO())

    assert Host.objects.get().hostname == "mdb.westcode.de"
    assert HostContainer.objects.count() == 0
