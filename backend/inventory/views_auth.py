import hmac
import logging

import requests
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.utils.html import format_html, format_html_join
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from inventory.entra import (
    EntraError,
    bind_team_member,
    build_authorization_url,
    exchange_code,
    fetch_jwks,
    validate_id_token,
)
from inventory.models import TeamMember
from inventory.permissions import active_member


logger = logging.getLogger(__name__)


def serialize_me(member: TeamMember) -> dict:
    return {
        "id": member.id,
        "name": member.name,
        "email": member.email,
        "github_username": member.github_username,
        "slack_user_id": member.slack_user_id,
        "layers": member.layers,
        "is_admin": member.is_admin,
        "is_default_infra_owner": member.is_default_infra_owner,
    }


class HealthView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request: Request) -> Response:
        return Response({"status": "ok"})


@method_decorator(ensure_csrf_cookie, name="get")
class MeView(APIView):
    def get(self, request: Request) -> Response:
        return Response(serialize_me(active_member(request)))


class LogoutView(APIView):
    def post(self, request: Request) -> Response:
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class DevLoginView(APIView):
    """Local development only; the route is registered only when DEBUG and PATCHBOT_DEV_LOGIN=1."""

    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        email = str(request.data.get("email", "")).strip().lower()
        member = TeamMember.objects.filter(email=email, is_active=True).first()
        if member is None:
            return Response({"detail": "Unknown team member."}, status=status.HTTP_400_BAD_REQUEST)
        if member.user is None:
            member.user = get_user_model().objects.create_user(username=member.email, email=member.email)
            member.save(update_fields=["user"])
        login(request, member.user)
        form_types = ("application/x-www-form-urlencoded", "multipart/form-data")
        if request.content_type.split(";")[0].strip() in form_types:  # the dev login page's form
            return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
        return Response(serialize_me(member))


def _dev_login_page() -> HttpResponse:
    """Stand-in for the Entra redirect in local development (DEBUG + PATCHBOT_DEV_LOGIN=1 only)."""
    buttons = format_html_join(
        "\n",
        '<button name="email" value="{}">{} <small>{}{}</small></button>',
        (
            (m.email, m.name, m.email, " · Admin" if m.is_admin else "")
            for m in TeamMember.objects.filter(is_active=True).order_by("-is_admin", "name")
        ),
    )
    body = format_html(
        """<!doctype html><html lang="de"><head><meta charset="utf-8"><title>Patchbot – Dev-Login</title>
<style>body{{font:15px system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#111}}
p{{color:#555}}button{{display:block;width:100%;text-align:left;margin:.4rem 0;padding:.7rem .9rem;font:inherit;
border:1px solid #ccc;border-radius:6px;background:#fff;cursor:pointer}}button:hover{{background:#eef}}
small{{color:#666;margin-left:.4rem}}</style></head><body>
<h1>Dev-Login</h1><p>Entra ID ist lokal nicht konfiguriert. Nur mit DEBUG und PATCHBOT_DEV_LOGIN=1 sichtbar.</p>
<form method="post" action="/api/auth/dev-login/">{}</form>{}</body></html>""",
        buttons,
        "" if buttons else format_html("<p>Keine aktiven Teammitglieder – erst <code>manage.py seed_dev</code>.</p>"),
    )
    return HttpResponse(body)


def _redirect_uri(request: HttpRequest) -> str:
    return settings.MICROSOFT_REDIRECT_URI or request.build_absolute_uri("/api/auth/entra/callback/")


@require_GET
def entra_login(request: HttpRequest) -> HttpResponse:
    if not (settings.MICROSOFT_TENANT_ID and settings.MICROSOFT_CLIENT_ID):
        if settings.PATCHBOT_DEV_LOGIN_ENABLED:
            return _dev_login_page()
        return HttpResponse("Entra ID login is not configured.", status=503)
    url = build_authorization_url(
        request.session,
        tenant_id=settings.MICROSOFT_TENANT_ID,
        client_id=settings.MICROSOFT_CLIENT_ID,
        redirect_uri=_redirect_uri(request),
    )
    return HttpResponseRedirect(url)


@require_GET
def entra_callback(request: HttpRequest) -> HttpResponse:
    expected_state = request.session.pop("entra_state", "")
    nonce = request.session.pop("entra_nonce", "")
    verifier = request.session.pop("entra_code_verifier", "")
    state = request.GET.get("state", "")
    code = request.GET.get("code", "")
    if not expected_state or not code or not hmac.compare_digest(state, expected_state):
        return HttpResponse("Ungültige Anmeldeanfrage.", status=400)
    try:
        tokens = exchange_code(
            code,
            verifier,
            tenant_id=settings.MICROSOFT_TENANT_ID,
            client_id=settings.MICROSOFT_CLIENT_ID,
            client_secret=settings.MICROSOFT_CLIENT_SECRET,
            redirect_uri=_redirect_uri(request),
        )
        id_token = str(tokens.get("id_token", ""))
        try:
            claims = validate_id_token(
                id_token,
                jwks=fetch_jwks(settings.MICROSOFT_TENANT_ID),
                tenant_id=settings.MICROSOFT_TENANT_ID,
                client_id=settings.MICROSOFT_CLIENT_ID,
                nonce=nonce,
            )
        except EntraError:
            # Microsoft rotates signing keys; retry once with a fresh JWKS.
            claims = validate_id_token(
                id_token,
                jwks=fetch_jwks(settings.MICROSOFT_TENANT_ID, force=True),
                tenant_id=settings.MICROSOFT_TENANT_ID,
                client_id=settings.MICROSOFT_CLIENT_ID,
                nonce=nonce,
            )
        member = bind_team_member(claims)
    except EntraError as exc:
        logger.warning("Entra login refused: %s", exc)
        return HttpResponse("Anmeldung abgelehnt.", status=403)
    except requests.RequestException:
        logger.exception("Entra token exchange failed")
        return HttpResponse("Anmeldedienst nicht erreichbar.", status=502)
    login(request, member.user)
    return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
