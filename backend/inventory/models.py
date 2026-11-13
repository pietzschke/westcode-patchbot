from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

LAYER_CHOICES = ("infrastructure", "application")


class TeamMember(models.Model):
    """A Westcode team member; bound 1:1 to the Django user created on first Entra login."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="team_member",
    )
    entra_object_id = models.CharField(max_length=64, unique=True, null=True, blank=True, default=None)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    github_username = models.CharField(max_length=64, unique=True, null=True, blank=True, default=None)
    git_commit_emails = models.JSONField(default=list, blank=True)
    slack_user_id = models.CharField(max_length=32, null=True, blank=True, default=None)
    layers = models.JSONField(default=list, blank=True)
    is_default_infra_owner = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} <{self.email}>"

    def save(self, *args, **kwargs) -> None:
        self.email = (self.email or "").strip().lower()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        super().clean()
        unknown = set(self.layers or []) - set(LAYER_CHOICES)
        if unknown:
            raise ValidationError({"layers": f"Unknown layers: {sorted(unknown)}"})
        if self.is_default_infra_owner and self.is_active:
            others = TeamMember.objects.filter(is_default_infra_owner=True, is_active=True).exclude(pk=self.pk)
            if others.exists():
                raise ValidationError(
                    {"is_default_infra_owner": "Only one active team member can be the default infra owner."}
                )


class Project(models.Model):
    """An active Westcode project, synced read-only from Notion."""

    slug = models.SlugField(max_length=128, unique=True)
    name = models.CharField(max_length=255)
    customer_name = models.CharField(max_length=255, blank=True, default="")
    is_internal = models.BooleanField(default=False)
    logo_key = models.CharField(max_length=64, default="westcode")
    notion_page_id = models.CharField(max_length=64, unique=True, null=True, blank=True, default=None)
    notion_status = models.CharField(max_length=64, blank=True, default="")
    notion_missing = models.BooleanField(default=False)
    last_notion_synced_at = models.DateTimeField(null=True, blank=True, default=None)
    owner = models.ForeignKey(
        TeamMember,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="owned_projects",
    )
    is_monitored = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class RepositoryAsset(models.Model):
    """A westcoder/* GitHub repository linked to a project."""

    DEPLOYMENT_MODES = [
        ("CONTAINER", "Container image"),
        ("HOST_CHECKOUT", "Git checkout on host"),
        ("NONE", "Not deployed"),
        ("UNKNOWN", "Unknown"),
    ]

    full_name = models.CharField(max_length=255, unique=True)
    default_branch = models.CharField(max_length=128, default="main")
    is_archived = models.BooleanField(default=False)
    project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="repositories",
    )
    suggested_project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="suggested_repositories",
    )
    deployment_mode = models.CharField(max_length=16, choices=DEPLOYMENT_MODES, default="UNKNOWN")
    has_bot_updates = models.BooleanField(default=False)
    last_scanned_at = models.DateTimeField(null=True, blank=True, default=None)
    last_scanned_commit_sha = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        ordering = ["full_name"]

    def __str__(self) -> str:
        return self.full_name
