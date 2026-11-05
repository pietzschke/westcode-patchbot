from django.urls import URLPattern, URLResolver, path
from fleet.api import AgentReportView
from rollouts.api import (
    HostDetailView,
    HostListView,
    HostTokenGenerateView,
    LiveSyncView,
    ProjectListView,
    ServiceListView,
)

urlpatterns: list[URLPattern | URLResolver] = [
    path("api/agent/report/", AgentReportView.as_view(), name="agent-report"),
    path("api/sync/", LiveSyncView.as_view(), name="live-sync"),
    path("api/projects/", ProjectListView.as_view(), name="project-list"),
    path("api/services/", ServiceListView.as_view(), name="service-list"),
    path("api/hosts/", HostListView.as_view(), name="host-list"),
    path("api/hosts/<slug:slug>/", HostDetailView.as_view(), name="host-detail"),
    path("api/hosts/<slug:slug>/token/", HostTokenGenerateView.as_view(), name="host-token-generate"),
]
