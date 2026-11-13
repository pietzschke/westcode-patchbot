import pytest

from controlplane.serializers import finding_summary
from testing.factories import make_finding


@pytest.mark.django_db
def test_os_eol_finding_gets_a_readable_title():
    f = make_finding(layer="INFRASTRUCTURE", ecosystem="ubuntu", package_name="__os_eol__",
                     current_version="20.04", target_version="24.04", vulnerability_ids=[])
    assert finding_summary(f)["title"] == "Betriebssystem-EOL: Ubuntu 20.04 → 24.04"


@pytest.mark.django_db
def test_package_finding_title_is_name_and_target_version():
    f = make_finding(package_name="lodash", target_version="4.17.21")
    assert finding_summary(f)["title"] == "lodash 4.17.21"
