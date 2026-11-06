from django.dispatch import Signal

# Sent when a project's monitoring flag actually changes.
# kwargs: project (Project), monitored (bool), source (str: WEB | NOTION)
project_monitoring_changed = Signal()
