from datetime import date
from pathlib import Path
import pytest
from fleet.infra_sync import is_distro_eol, sync_infra_hosts
from fleet.models import Host


@pytest.mark.django_db
def test_sync_infra_hosts_parses_real_westcode_infra():
    infra_path = Path("/Users/pietzschke/projects/westcode-infra")
    hosts = sync_infra_hosts(infra_path)
    stack_names = {h.stack_name for h in hosts}

    assert len(hosts) == 23
    assert "hetzner-westcode-tiles" not in stack_names
    assert "ionos-westcode" in stack_names

    linklama = Host.objects.get(stack_name="hetzner-linklama")
    assert linklama.declared_image == "ubuntu-20.04"
    assert linklama.is_os_eol is True

    masteroil = Host.objects.get(stack_name="hetzner-masteroil")
    assert masteroil.declared_image is None

    null_image_hosts = set(Host.objects.filter(declared_image__isnull=True).values_list("hostname", flat=True))
    assert null_image_hosts == {
        "dev.brockhaus.westcode.network",
        "masteroil.westcode.network",
        "urh-1",
    }


def test_is_distro_eol_flags_ubuntu_20_04():
    assert is_distro_eol("ubuntu", "20.04", today=date(2026, 11, 3)) is True
    assert is_distro_eol("ubuntu", "24.04", today=date(2026, 11, 3)) is False
    assert is_distro_eol("debian", "13", today=date(2026, 11, 3)) is False


@pytest.mark.django_db
def test_sync_infra_hosts_preserves_live_reported_os_info_on_null_image_hosts():
    infra_path = Path("/Users/pietzschke/projects/westcode-infra")
    sync_infra_hosts(infra_path)

    masteroil = Host.objects.get(stack_name="hetzner-masteroil")
    assert masteroil.declared_image is None
    masteroil.os_distro = "ubuntu"
    masteroil.os_version = "20.04"
    masteroil.is_os_eol = True
    masteroil.save(update_fields=["os_distro", "os_version", "is_os_eol"])

    sync_infra_hosts(infra_path)
    masteroil.refresh_from_db()
    assert masteroil.declared_image is None
    assert masteroil.os_distro == "ubuntu"
    assert masteroil.os_version == "20.04"
    assert masteroil.is_os_eol is True


def _infra(tmp_path, image: str) -> Path:
    stack = tmp_path / "stacks" / "hetzner-mdb"
    stack.mkdir(parents=True, exist_ok=True)
    (stack / "servers.tf").write_text(
        'resource "hcloud_server" "mdb" {\n'
        '  name  = "mdb.westcode.de"\n'
        f'  image = "{image}"\n'
        "}\n"
    )
    return tmp_path


@pytest.mark.django_db
def test_sync_fills_os_data_and_eol_date_for_hosts_that_never_reported(tmp_path):
    sync_infra_hosts(_infra(tmp_path, "ubuntu-20.04"), today=date(2026, 11, 5))
    host = Host.objects.get(hostname="mdb.westcode.de")
    assert (host.os_distro, host.os_version) == ("ubuntu", "20.04")
    assert host.is_os_eol is True
    assert host.os_eol_date == date(2025, 5, 31)

    # servers.tf changes before the agent ever reported: the declared image is still the best data we have.
    sync_infra_hosts(_infra(tmp_path, "ubuntu-24.04"), today=date(2026, 11, 5))
    host.refresh_from_db()
    assert (host.os_version, host.is_os_eol, host.os_eol_date) == ("24.04", False, date(2029, 5, 31))


@pytest.mark.django_db
def test_sync_does_not_overwrite_agent_reported_os_data(tmp_path):
    from django.utils import timezone

    infra = _infra(tmp_path, "ubuntu-20.04")
    sync_infra_hosts(infra, today=date(2026, 11, 5))
    # The VM was release-upgraded in place; the agent reports the live OS (servers.tf still says 20.04).
    Host.objects.filter(hostname="mdb.westcode.de").update(
        os_distro="ubuntu", os_version="24.04", is_os_eol=False, os_eol_date=date(2029, 5, 31),
        last_seen_at=timezone.now(),
    )

    sync_infra_hosts(infra, today=date(2026, 11, 5))
    host = Host.objects.get(hostname="mdb.westcode.de")
    assert host.declared_image == "ubuntu-20.04"
    assert (host.os_distro, host.os_version) == ("ubuntu", "24.04")
    assert host.is_os_eol is False
    assert host.os_eol_date == date(2029, 5, 31)
