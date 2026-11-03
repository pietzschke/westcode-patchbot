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
