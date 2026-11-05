import hashlib
from pathlib import Path

import pytest
import yaml
from django.core.exceptions import ImproperlyConfigured
from django.urls import Resolver404, resolve
from rest_framework.test import APIClient

from config.checks import DEV_SECRET_KEY, validate_dev_login, validate_secret_key
from testing.factories import make_host, make_user_with_member

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.django_db
def test_api_requires_login_by_default():
    assert APIClient().get("/api/hosts/").status_code == 403


@pytest.mark.django_db
def test_health_is_public_and_leaks_nothing():
    resp = APIClient().get("/api/health/")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.django_db
def test_agent_report_still_uses_host_token():
    make_host(slug="mdb", hostname="mdb.westcode.de", agent_token_hash=hashlib.sha256(b"tok").hexdigest())
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Bearer tok")
    resp = client.post(
        "/api/agent/report/",
        data={"hostname": "mdb.westcode.de", "packages": [], "containers": []},
        format="json",
    )
    assert resp.status_code == 200


@pytest.mark.django_db
def test_me_returns_bound_team_member():
    user, _ = make_user_with_member(email="moritz.pietzschke@westcode.de", name="Moritz Pietzschke")
    client = APIClient()
    client.force_login(user)
    resp = client.get("/api/auth/me/")
    assert resp.status_code == 200
    assert resp.json()["email"] == "moritz.pietzschke@westcode.de"
    assert resp.json()["is_admin"] is False


@pytest.mark.django_db
def test_deactivated_member_loses_access_immediately():
    user, member = make_user_with_member(email="ex@westcode.de")
    client = APIClient()
    client.force_login(user)
    member.is_active = False
    member.save()
    assert client.get("/api/auth/me/").status_code == 403


@pytest.mark.django_db
def test_user_without_team_member_is_rejected():
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.create_user(username="stranger", email="stranger@example.com")
    client = APIClient()
    client.force_login(user)
    assert client.get("/api/hosts/").status_code == 403


@pytest.mark.django_db
def test_admin_only_endpoint_rejects_regular_member():
    make_host(slug="mdb", hostname="mdb.westcode.de")
    user, _ = make_user_with_member(email="dev@westcode.de", is_admin=False)
    admin, _ = make_user_with_member(email="admin@westcode.de", is_admin=True)
    client = APIClient()
    client.force_login(user)
    assert client.post("/api/hosts/mdb/token/").status_code == 403
    client.force_login(admin)
    assert client.post("/api/hosts/mdb/token/").status_code in (200, 201)


@pytest.mark.django_db
def test_unsafe_methods_require_csrf_token():
    make_host(slug="mdb", hostname="mdb.westcode.de")
    admin, _ = make_user_with_member(email="admin@westcode.de", is_admin=True)
    client = APIClient(enforce_csrf_checks=True)
    client.force_login(admin)
    assert client.post("/api/hosts/mdb/token/").status_code == 403


def test_dev_login_route_absent_without_dev_mode():
    with pytest.raises(Resolver404):
        resolve("/api/auth/dev-login/")


def test_dev_login_refused_without_debug():
    with pytest.raises(ImproperlyConfigured):
        validate_dev_login(debug=False, flag="1")
    validate_dev_login(debug=True, flag="1")
    validate_dev_login(debug=False, flag=None)


def test_production_requires_real_secret_key():
    with pytest.raises(ImproperlyConfigured):
        validate_secret_key(debug=False, secret_key=DEV_SECRET_KEY)
    with pytest.raises(ImproperlyConfigured):
        validate_secret_key(debug=False, secret_key="")
    validate_secret_key(debug=True, secret_key=DEV_SECRET_KEY)
    validate_secret_key(debug=False, secret_key="a-real-production-secret-value-0123456789")


def test_compose_healthcheck_uses_public_health_endpoint():
    compose = yaml.safe_load((REPO_ROOT / "deploy/compose.yaml").read_text())
    healthcheck = " ".join(compose["services"]["web"]["healthcheck"]["test"])
    assert "/api/health/" in healthcheck


@pytest.mark.django_db
def test_me_sets_csrf_cookie_for_the_spa():
    user, _ = make_user_with_member(email="spa@westcode.de")
    client = APIClient()
    client.force_login(user)
    resp = client.get("/api/auth/me/")
    assert "csrftoken" in resp.cookies
