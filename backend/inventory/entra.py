"""Single-tenant Microsoft Entra ID login (OIDC authorization code flow with PKCE).

Identity rules (spec v2.1 §7.1):
- the ID token is validated against the tenant JWKS (signature, iss, aud, tid, nonce, exp/nbf);
- the first login binds a TeamMember by @westcode.de email and stores the immutable ``oid``;
- every later login matches on ``oid`` only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any, Callable
from urllib.parse import urlencode

import jwt
import requests
from django.contrib.auth import get_user_model
from django.db import transaction

from config.checks import validate_tenant_id  # noqa: F401  (re-exported for callers and tests)
from inventory.models import TeamMember

ALLOWED_EMAIL_DOMAIN = "@westcode.de"
AUTHORITY = "https://login.microsoftonline.com"
JWKS_CACHE_SECONDS = 3600

_jwks_cache: dict[str, tuple[float, dict]] = {}


class EntraError(Exception):
    """The login must be refused."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_authorization_url(session, *, tenant_id: str, client_id: str, redirect_uri: str) -> str:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    session["entra_state"] = state
    session["entra_nonce"] = nonce
    session["entra_code_verifier"] = verifier
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
        "code_challenge_method": "S256",
    }
    return f"{AUTHORITY}/{tenant_id}/oauth2/v2.0/authorize?{urlencode(params)}"


def exchange_code(
    code: str,
    verifier: str,
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    post: Callable[..., Any] = requests.post,
) -> dict:
    resp = post(
        f"{AUTHORITY}/{tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_jwks(tenant_id: str, *, get: Callable[..., Any] = requests.get, force: bool = False) -> dict:
    cached = _jwks_cache.get(tenant_id)
    if cached and not force and time.monotonic() - cached[0] < JWKS_CACHE_SECONDS:
        return cached[1]
    resp = get(f"{AUTHORITY}/{tenant_id}/discovery/v2.0/keys", timeout=10)
    resp.raise_for_status()
    jwks = resp.json()
    _jwks_cache[tenant_id] = (time.monotonic(), jwks)
    return jwks


def validate_id_token(
    id_token: str, *, jwks: dict, tenant_id: str, client_id: str, nonce: str, leeway: int = 60
) -> dict:
    try:
        kid = jwt.get_unverified_header(id_token).get("kid")
        jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if jwk is None:
            raise EntraError("ID token signed with an unknown key.")
        claims = jwt.decode(
            id_token,
            key=jwt.PyJWK(jwk).key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=f"{AUTHORITY}/{tenant_id}/v2.0",
            leeway=leeway,
            options={"require": ["exp", "nbf", "iat", "aud", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise EntraError(f"Invalid ID token: {exc}") from exc
    if not hmac.compare_digest(str(claims.get("tid", "")), tenant_id):
        raise EntraError("ID token belongs to another tenant.")
    if not nonce or not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise EntraError("ID token nonce mismatch.")
    return claims


def _ensure_user(member: TeamMember) -> None:
    if member.user is None:
        member.user = get_user_model().objects.create_user(
            username=f"entra:{member.entra_object_id}", email=member.email
        )


@transaction.atomic
def bind_team_member(claims: dict) -> TeamMember:
    oid = str(claims.get("oid") or "").strip()
    if not oid:
        raise EntraError("ID token has no object id.")

    member = TeamMember.objects.select_for_update().filter(entra_object_id=oid).first()
    if member is None:
        email = str(claims.get("email") or claims.get("preferred_username") or "").strip().lower()
        if not email.endswith(ALLOWED_EMAIL_DOMAIN):
            raise EntraError("Only @westcode.de accounts may sign in.")
        member = TeamMember.objects.select_for_update().filter(email=email).first()
        if member is None:
            raise EntraError("No team member with this email.")
        if member.entra_object_id and member.entra_object_id != oid:
            raise EntraError("This team member is already bound to another Entra identity.")
        member.entra_object_id = oid

    if not member.is_active:
        raise EntraError("Team member is deactivated.")
    _ensure_user(member)
    member.save(update_fields=["entra_object_id", "user"])
    return member
