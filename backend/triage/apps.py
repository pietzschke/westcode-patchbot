from django.apps import AppConfig


class TriageConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "triage"

    def ready(self) -> None:
        from inventory.signals import project_monitoring_changed
        from triage.lifecycle import on_monitoring_changed

        project_monitoring_changed.connect(on_monitoring_changed, dispatch_uid="triage.on_monitoring_changed")
