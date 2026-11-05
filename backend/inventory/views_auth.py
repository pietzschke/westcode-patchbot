import hmac
import logging

import requests
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
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
        return Response(serialize_me(member))


def _redirect_uri(request: HttpRequest) -> str:
    return settings.MICROSOFT_REDIRECT_URI or request.build_absolute_uri("/api/auth/entra/callback/")


@require_GET
def entra_login(request: HttpRequest) -> HttpResponse:
    if not (settings.MICROSOFT_TENANT_ID and settings.MICROSOFT_CLIENT_ID):
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
