"""Local dev login page: shown instead of the Entra redirect only when DEBUG + PATCHBOT_DEV_LOGIN=1."""

import pytest
from django.test import Client
from django.urls import include, path

from inventory.views_auth import DevLoginView
from testing.factories import make_member

# The dev-login route is only registered at import time in dev mode, so tests use their own URLconf.
urlpatterns = [
    path("api/auth/dev-login/", DevLoginView.as_view(), name="auth-dev-login"),
    path("", include("config.urls")),
]


@pytest.mark.django_db
def test_entra_login_without_config_and_without_dev_mode_is_503(settings):
    settings.MICROSOFT_TENANT_ID = ""
    settings.PATCHBOT_DEV_LOGIN_ENABLED = False
    resp = Client().get("/api/auth/entra/login/")
    assert resp.status_code == 503


@pytest.mark.django_db
def test_entra_login_shows_dev_login_form_in_dev_mode(settings):
    settings.MICROSOFT_TENANT_ID = ""
    settings.PATCHBOT_DEV_LOGIN_ENABLED = True
    make_member(email="anna@westcode.de", name="Anna <Admin>")
    make_member(email="tim@westcode.de", name="Tim", is_active=False)
    resp = Client().get("/api/auth/entra/login/")
    assert resp.status_code == 200
    html = resp.content.decode()
    assert 'action="/api/auth/dev-login/"' in html
    assert 'value="anna@westcode.de"' in html
    assert "Anna &lt;Admin&gt;" in html  # escaped
    assert "tim@westcode.de" not in html  # inactive members cannot log in


@pytest.mark.django_db
def test_entra_is_used_when_configured_even_in_dev_mode(settings):
    settings.MICROSOFT_TENANT_ID = "11111111-1111-1111-1111-111111111111"
    settings.MICROSOFT_CLIENT_ID = "client"
    settings.PATCHBOT_DEV_LOGIN_ENABLED = True
    resp = Client().get("/api/auth/entra/login/")
    assert resp.status_code == 302
    assert resp["Location"].startswith("https://login.microsoftonline.com/")


@pytest.mark.django_db
@pytest.mark.urls(__name__)
def test_dev_login_form_post_logs_in_and_redirects_to_the_app():
    make_member(email="anna@westcode.de")
    client = Client()
    resp = client.post("/api/auth/dev-login/", {"email": "anna@westcode.de"})
    assert resp.status_code == 302
    assert resp["Location"] == "/"
    assert client.get("/api/auth/me/").json()["email"] == "anna@westcode.de"


@pytest.mark.django_db
@pytest.mark.urls(__name__)
def test_dev_login_json_post_still_returns_the_member():
    make_member(email="anna@westcode.de")
    resp = Client().post("/api/auth/dev-login/", {"email": "anna@westcode.de"}, content_type="application/json")
    assert resp.status_code == 200
    assert resp.json()["email"] == "anna@westcode.de"
