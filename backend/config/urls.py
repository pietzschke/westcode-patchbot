from django.urls import URLPattern, URLResolver, path
from fleet.api import AgentJobResultView, AgentNextJobView, AgentReportView
from rollouts.api import (
    HostDetailView,
    HostListView,
    HostTokenGenerateView,
    LiveSyncView,
    RolloutPlanDetailView,
    RolloutPlanExecuteView,
    RolloutPlanListView,
    ServiceListView,
    ServicePlanCreateView,
)

urlpatterns: list[URLPattern | URLResolver] = [
    path("api/agent/report/", AgentReportView.as_view(), name="agent-report"),
    path("api/agent/jobs/next/", AgentNextJobView.as_view(), name="agent-next-job"),
    path("api/agent/jobs/<uuid:job_id>/result/", AgentJobResultView.as_view(), name="agent-job-result"),
    path("api/sync/", LiveSyncView.as_view(), name="live-sync"),
    path("api/services/", ServiceListView.as_view(), name="service-list"),
    path("api/services/<slug:slug>/plan/", ServicePlanCreateView.as_view(), name="service-plan-create"),
    path("api/plans/", RolloutPlanListView.as_view(), name="rollout-plan-list"),
    path("api/plans/<uuid:plan_id>/", RolloutPlanDetailView.as_view(), name="rollout-plan-detail"),
    path("api/plans/<uuid:plan_id>/execute/", RolloutPlanExecuteView.as_view(), name="rollout-plan-execute"),
    path("api/hosts/", HostListView.as_view(), name="host-list"),
    path("api/hosts/<slug:slug>/", HostDetailView.as_view(), name="host-detail"),
    path("api/hosts/<slug:slug>/token/", HostTokenGenerateView.as_view(), name="host-token-generate"),
]
