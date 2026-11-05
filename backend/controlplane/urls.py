from django.urls import path

from controlplane import views

urlpatterns = [
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),
    path("findings/<int:finding_id>/", views.FindingDetailView.as_view(), name="finding-detail"),
    path("findings/<int:finding_id>/acknowledge/", views.AcknowledgeView.as_view(), name="finding-acknowledge"),
    path("findings/<int:finding_id>/dismiss/", views.DismissView.as_view(), name="finding-dismiss"),
    path("findings/<int:finding_id>/reopen/", views.ReopenView.as_view(), name="finding-reopen"),
    path("findings/<int:finding_id>/extend/", views.ExtendView.as_view(), name="finding-extend"),
    path("maintenance/<int:update_id>/request-analysis/", views.MaintenanceAnalysisView.as_view(), name="maintenance-analysis"),
    path("triage-projects/", views.ProjectsView.as_view(), name="triage-projects"),
    path("triage-projects/sync-notion/", views.NotionSyncView.as_view(), name="triage-projects-sync"),
    path("triage-projects/<slug:slug>/monitoring/", views.MonitoringView.as_view(), name="triage-project-monitoring"),
    path("assets/<str:asset_type>/<int:asset_id>/confirm-suggestion/", views.AssetConfirmView.as_view(), name="asset-confirm"),
    path("assets/<str:asset_type>/<int:asset_id>/assign/", views.AssetAssignView.as_view(), name="asset-assign"),
    path("repositories/<int:repo_id>/", views.RepositoryView.as_view(), name="repository"),
    path("team/", views.TeamListView.as_view(), name="team"),
    path("team/<int:member_id>/", views.TeamDetailView.as_view(), name="team-member"),
    path("team/<int:member_id>/test-dm/", views.TeamTestDmView.as_view(), name="team-test-dm"),
    path("scans/run/", views.ScanRunView.as_view(), name="scan-run"),
]
