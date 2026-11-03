from django.urls import URLPattern, URLResolver, path
from fleet.api import AgentJobResultView, AgentNextJobView, AgentReportView

urlpatterns: list[URLPattern | URLResolver] = [
    path("api/agent/report/", AgentReportView.as_view(), name="agent-report"),
    path("api/agent/jobs/next/", AgentNextJobView.as_view(), name="agent-next-job"),
    path("api/agent/jobs/<uuid:job_id>/result/", AgentJobResultView.as_view(), name="agent-job-result"),
]
