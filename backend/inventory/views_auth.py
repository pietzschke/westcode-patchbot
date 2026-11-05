from django.contrib.auth import get_user_model, login, logout
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from inventory.models import TeamMember
from inventory.permissions import active_member


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
