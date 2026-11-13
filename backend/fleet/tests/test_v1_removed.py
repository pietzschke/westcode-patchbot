import pytest
from django.urls import Resolver404, resolve


@pytest.mark.parametrize("path", ["/api/services/", "/api/sync/", "/api/projects/"])
def test_v1_dashboard_endpoints_removed(path):
    with pytest.raises(Resolver404):
        resolve(path)


@pytest.mark.parametrize("path", ["/api/hosts/", "/api/hosts/mdb/", "/api/hosts/mdb/token/"])
def test_host_endpoints_still_resolve(path):
    resolve(path)
