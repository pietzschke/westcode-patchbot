from django.db import models


class Host(models.Model):
    slug = models.CharField(max_length=128, unique=True)
    hostname = models.CharField(max_length=255, unique=True)
    provider = models.CharField(max_length=32)
    stack_name = models.CharField(max_length=128)
    declared_image = models.CharField(max_length=128, null=True, blank=True, default=None)
    os_distro = models.CharField(max_length=64, blank=True, default="")
    os_version = models.CharField(max_length=64, blank=True, default="")
    is_os_eol = models.BooleanField(default=False)
    os_eol_date = models.DateField(null=True, blank=True, default=None)
    kernel_version = models.CharField(max_length=128, blank=True, default="")
    reboot_required = models.BooleanField(default=False)
    apt_lists_updated_at = models.DateTimeField(null=True, blank=True, default=None)
    agent_version = models.CharField(max_length=32, blank=True, default="")
    project = models.ForeignKey(
        "inventory.Project", null=True, blank=True, on_delete=models.SET_NULL, related_name="hosts"
    )
    suggested_project = models.ForeignKey(
        "inventory.Project", null=True, blank=True, on_delete=models.SET_NULL, related_name="suggested_hosts"
    )
    agent_token_hash = models.CharField(max_length=128, blank=True, default="")
    last_seen_at = models.DateTimeField(null=True, blank=True, default=None)

    class Meta:
        ordering = ["hostname"]

    def __str__(self) -> str:
        return f"{self.hostname} ({self.stack_name})"


class HostPackage(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="packages")
    name = models.CharField(max_length=255)
    installed_version = models.CharField(max_length=128)
    candidate_version = models.CharField(max_length=128, blank=True, default="")
    is_security_update = models.BooleanField(default=False)
    source_pocket = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.host.hostname}:{self.name} ({self.installed_version} -> {self.candidate_version})"


class HostContainer(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="containers")
    container_id = models.CharField(max_length=128)
    name = models.CharField(max_length=255)
    image_tag = models.CharField(max_length=512)
    image_id = models.CharField(max_length=255)
    repo_digests = models.JSONField(default=list)
    oci_title = models.CharField(max_length=255, blank=True, default="")
    oci_revision = models.CharField(max_length=128, blank=True, default="")
    oci_source = models.CharField(max_length=512, blank=True, default="")
    image_created_at = models.DateTimeField(null=True, blank=True, default=None)
    working_dir = models.CharField(max_length=512, blank=True, default="")
    compose_service = models.CharField(max_length=255, blank=True, default="")
    git_head_sha = models.CharField(max_length=64, blank=True, default="")
    git_clean = models.BooleanField(null=True, blank=True, default=None)
    status = models.CharField(max_length=64, default="running")
    reported_at = models.DateTimeField(null=True, blank=True, default=None)
    project = models.ForeignKey(
        "inventory.Project", null=True, blank=True, on_delete=models.SET_NULL, related_name="containers"
    )
    suggested_project = models.ForeignKey(
        "inventory.Project", null=True, blank=True, on_delete=models.SET_NULL, related_name="suggested_containers"
    )
    repository = models.ForeignKey(
        "inventory.RepositoryAsset",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="running_containers",
    )

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.host.hostname}:{self.name} ({self.image_tag})"

