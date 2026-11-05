from django.conf import settings
from django.urls import URLPattern, URLResolver, path
from fleet.api import AgentReportView
from inventory.views_auth import DevLoginView, HealthView, LogoutView, MeView, entra_callback, entra_login
from triage.webhooks import github_webhook, slack_interactions
from rollouts.api import (
    HostDetailView,
    HostListView,
    HostTokenGenerateView,
    LiveSyncView,
    ProjectListView,
    ServiceListView,
)

urlpatterns: list[URLPattern | URLResolver] = [
    path("api/health/", HealthView.as_view(), name="health"),
    path("api/auth/me/", MeView.as_view(), name="auth-me"),
    path("api/auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("api/auth/entra/login/", entra_login, name="auth-entra-login"),
    path("api/auth/entra/callback/", entra_callback, name="auth-entra-callback"),
    path("api/agent/report/", AgentReportView.as_view(), name="agent-report"),
    path("api/webhooks/slack/interactions/", slack_interactions, name="webhook-slack"),
    path("api/webhooks/github/", github_webhook, name="webhook-github"),
    path("api/sync/", LiveSyncView.as_view(), name="live-sync"),
    path("api/projects/", ProjectListView.as_view(), name="project-list"),
    path("api/services/", ServiceListView.as_view(), name="service-list"),
    path("api/hosts/", HostListView.as_view(), name="host-list"),
    path("api/hosts/<slug:slug>/", HostDetailView.as_view(), name="host-detail"),
    path("api/hosts/<slug:slug>/token/", HostTokenGenerateView.as_view(), name="host-token-generate"),
]

if settings.PATCHBOT_DEV_LOGIN_ENABLED:
    urlpatterns.append(path("api/auth/dev-login/", DevLoginView.as_view(), name="auth-dev-login"))
