import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.exceptions import ImproperlyConfigured
from jwt.algorithms import RSAAlgorithm

from inventory.entra import EntraError, bind_team_member, validate_id_token, validate_tenant_id
from testing.factories import make_member

TENANT = "8f1c2a8e-0000-4000-8000-000000000001"
CLIENT = "11111111-2222-3333-4444-555555555555"


def _keypair(kid="k1"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = kid
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem, {"keys": [jwk]}


@pytest.fixture(scope="module")
def keypair():
    return _keypair()


def _token(pem, kid="k1", **overrides):
    now = int(time.time())
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": CLIENT,
        "tid": TENANT,
        "oid": "oid-1",
        "nonce": "n1",
        "email": "Moritz.Pietzschke@westcode.de",
        "name": "Moritz Pietzschke",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
    }
    claims.update(overrides)
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})


def test_accepts_valid_token(keypair):
    pem, jwks = keypair
    claims = validate_id_token(_token(pem), jwks=jwks, tenant_id=TENANT, client_id=CLIENT, nonce="n1")
    assert claims["oid"] == "oid-1"


@pytest.mark.parametrize(
    "override",
    [
        {"aud": "other-client"},
        {"tid": "99999999-0000-4000-8000-000000000000"},
        {"iss": "https://login.microsoftonline.com/common/v2.0"},
        {"nonce": "replayed"},
        {"exp": int(time.time()) - 3600},
    ],
)
def test_rejects_invalid_claims(keypair, override):
    pem, jwks = keypair
    with pytest.raises(EntraError):
        validate_id_token(_token(pem, **override), jwks=jwks, tenant_id=TENANT, client_id=CLIENT, nonce="n1")


def test_rejects_token_signed_with_foreign_key(keypair):
    _, jwks = keypair
    foreign_pem, _ = _keypair()
    with pytest.raises(EntraError):
        validate_id_token(_token(foreign_pem), jwks=jwks, tenant_id=TENANT, client_id=CLIENT, nonce="n1")


def test_rejects_unknown_key_id(keypair):
    pem, jwks = keypair
    with pytest.raises(EntraError):
        validate_id_token(_token(pem, kid="other"), jwks=jwks, tenant_id=TENANT, client_id=CLIENT, nonce="n1")


@pytest.mark.parametrize("tenant", ["common", "organizations", "consumers", "westcode.de", ""])
def test_rejects_non_guid_tenant(tenant):
    with pytest.raises(ImproperlyConfigured):
        validate_tenant_id(tenant)


def test_accepts_guid_tenant():
    validate_tenant_id(TENANT)


@pytest.mark.django_db
def test_binds_by_email_first_then_by_oid():
    member = make_member(email="moritz.pietzschke@westcode.de")
    bound = bind_team_member({"oid": "oid-1", "email": "Moritz.Pietzschke@westcode.de", "name": "Moritz"})
    member.refresh_from_db()
    assert bound == member
    assert member.entra_object_id == "oid-1"
    assert member.user is not None

    member.email = "renamed@westcode.de"
    member.save()
    assert bind_team_member({"oid": "oid-1", "email": "someone-else@westcode.de"}) == member


@pytest.mark.django_db
def test_email_already_bound_to_other_oid_is_refused():
    make_member(email="moritz.pietzschke@westcode.de", entra_object_id="oid-original")
    with pytest.raises(EntraError):
        bind_team_member({"oid": "oid-attacker", "email": "moritz.pietzschke@westcode.de"})


@pytest.mark.django_db
@pytest.mark.parametrize(
    "claims",
    [
        {"oid": "x1", "email": "ex@westcode.de"},
        {"oid": "x2", "email": "nobody@westcode.de"},
        {"oid": "x3", "email": "moritz@gmail.com"},
        {"email": "noid@westcode.de"},
    ],
)
def test_refuses_inactive_unknown_foreign_or_missing_oid(claims):
    make_member(email="ex@westcode.de", is_active=False)
    make_member(email="noid@westcode.de")
    with pytest.raises(EntraError):
        bind_team_member(claims)


@pytest.mark.django_db
def test_login_redirect_uses_pkce_and_stores_state(client, settings):
    settings.MICROSOFT_TENANT_ID = TENANT
    settings.MICROSOFT_CLIENT_ID = CLIENT
    resp = client.get("/api/auth/entra/login/")
    assert resp.status_code == 302
    url = urlparse(resp["Location"])
    query = parse_qs(url.query)
    assert url.netloc == "login.microsoftonline.com"
    assert url.path == f"/{TENANT}/oauth2/v2.0/authorize"
    assert query["code_challenge_method"] == ["S256"]
    assert query["client_id"] == [CLIENT]
    assert client.session["entra_state"] == query["state"][0]
    assert "entra_code_verifier" in client.session


@pytest.mark.django_db
def test_login_without_configuration_is_unavailable(client, settings):
    settings.MICROSOFT_TENANT_ID = ""
    assert client.get("/api/auth/entra/login/").status_code == 503


@pytest.mark.django_db
def test_callback_rejects_state_mismatch(client, settings):
    settings.MICROSOFT_TENANT_ID = TENANT
    settings.MICROSOFT_CLIENT_ID = CLIENT
    client.get("/api/auth/entra/login/")
    assert client.get("/api/auth/entra/callback/?code=abc&state=forged").status_code == 400


@pytest.mark.django_db
def test_callback_logs_in_bound_member(client, settings, monkeypatch, keypair):
    import inventory.views_auth as views

    pem, jwks = keypair
    settings.MICROSOFT_TENANT_ID = TENANT
    settings.MICROSOFT_CLIENT_ID = CLIENT
    settings.MICROSOFT_CLIENT_SECRET = "secret"
    member = make_member(email="moritz.pietzschke@westcode.de")

    client.get("/api/auth/entra/login/")
    state = client.session["entra_state"]
    nonce = client.session["entra_nonce"]
    monkeypatch.setattr(views, "exchange_code", lambda *a, **kw: {"id_token": _token(pem, nonce=nonce)})
    monkeypatch.setattr(views, "fetch_jwks", lambda *a, **kw: jwks)

    resp = client.get(f"/api/auth/entra/callback/?code=abc&state={state}")

    assert resp.status_code == 302
    assert resp["Location"] == "/"
    me = client.get("/api/auth/me/")
    assert me.status_code == 200
    assert me.json()["id"] == member.id
