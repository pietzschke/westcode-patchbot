from rest_framework.permissions import BasePermission


def active_member(request):
    """Return the active TeamMember behind the session, or None."""
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return None
    member = getattr(user, "team_member", None)
    if member is None or not member.is_active:
        return None
    return member


class IsTeamMember(BasePermission):
    """Default permission: an authenticated user bound to an active TeamMember."""

    def has_permission(self, request, view) -> bool:
        return active_member(request) is not None


class IsTeamAdmin(BasePermission):
    def has_permission(self, request, view) -> bool:
        member = active_member(request)
        return member is not None and member.is_admin
