from pathlib import Path
from django.core.management.base import BaseCommand

from catalog.correlator import rebuild_service_groups
from fleet.infra_sync import sync_infra_hosts
from fleet.models import Host, HostContainer, HostPackage


class Command(BaseCommand):
    help = "Syncs the 23 real hosts from westcode-infra and seeds realistic service/CVE/Renovate data for local live testing."

    def handle(self, *args, **options):
        Host.objects.all().delete()
        infra_root = Path("/Users/pietzschke/projects/westcode-infra")
        hosts = sync_infra_hosts(infra_root)
        self.stdout.write(self.style.SUCCESS(f"Synced {len(hosts)} hosts from {infra_root}"))

        def get_host(slug: str) -> Host:
            return Host.objects.get(slug=slug)

        # 1. Plausible Analytics across 3 hosts
        for idx, slug in enumerate(("p-westcode-de", "c2-westcode-network", "wewhydrogen-com"), start=1):
            HostContainer.objects.create(
                host=get_host(slug),
                container_id=f"plausible-{idx:02d}",
                name="plausible",
                image_tag="ghcr.io/plausible/community-edition:v2.1.0",
                image_id="sha256:1111111111111111111111111111111111111111111111111111111111111111",
                repo_digests=["ghcr.io/plausible/community-edition@sha256:111111"],
                oci_title="plausible/analytics",
                oci_revision="2.1.0",
                working_dir="/opt/plausible",
                compose_service="plausible",
                git_clean=True,
            )

        # 2. Westcode Hub (ECR re-tagged container on service.westcode.de)
        HostContainer.objects.create(
            host=get_host("service-westcode-de"),
            container_id="hub-backend-01",
            name="hub-backend",
            image_tag="hub-backend:latest",
            image_id="sha256:2222222222222222222222222222222222222222222222222222222222222222",
            repo_digests=[
                "123456789012.dkr.ecr.eu-central-1.amazonaws.com/westcode-hub@sha256:222222"
            ],
            oci_title="westcode-hub",
            oci_revision="5.2.9",
            working_dir="/opt/hub",
            compose_service="hub-backend",
            git_clean=True,
        )

        # 3. PostgreSQL across 4 hosts
        for idx, (slug, ver) in enumerate(
            (
                ("c2-westcode-network", "16.2"),
                ("service-westcode-de", "16.2"),
                ("mdb-westcode-de", "16.3"),
                ("dev-westcode-de", "16.4"),
            ),
            start=1,
        ):
            HostContainer.objects.create(
                host=get_host(slug),
                container_id=f"postgres-{idx:02d}",
                name="db",
                image_tag=f"postgres:{ver}-alpine",
                image_id=f"sha256:333333333333333333333333333333333333333333333333333333333333{ver.replace('.', '')}",
                repo_digests=[f"postgres@sha256:3333{ver}"],
                oci_title="postgres",
                oci_revision=ver,
                working_dir="/opt/postgres",
                compose_service="db",
                git_clean=True,
            )

        # 4. Coder on remote.westcode.de
        HostContainer.objects.create(
            host=get_host("remote-westcode-de"),
            container_id="coder-01",
            name="coder",
            image_tag="ghcr.io/coder/coder:v2.18.0",
            image_id="sha256:4444444444444444444444444444444444444444444444444444444444444444",
            repo_digests=["ghcr.io/coder/coder@sha256:444444"],
            oci_title="coder/coder",
            oci_revision="2.18.0",
            working_dir="/opt/coder",
            compose_service="coder",
            git_clean=True,
        )

        # 5. Traefik across 3 hosts (one host with dirty /opt/traefik to showcase Pre-Check blocking!)
        for idx, (slug, is_clean) in enumerate(
            (("c2-westcode-network", True), ("service-westcode-de", True), ("dev-westcode-de", False)),
            start=1,
        ):
            HostContainer.objects.create(
                host=get_host(slug),
                container_id=f"traefik-{idx:02d}",
                name="traefik",
                image_tag="traefik:v3.1.2",
                image_id="sha256:5555555555555555555555555555555555555555555555555555555555555555",
                repo_digests=["traefik@sha256:555555"],
                oci_title="traefik",
                oci_revision="3.1.2",
                working_dir="/opt/traefik",
                compose_service="traefik",
                git_clean=is_clean,
            )

        # 6. Valhalla & TileServer GL
        HostContainer.objects.create(
            host=get_host("converter-westcode-de"),
            container_id="valhalla-01",
            name="valhalla",
            image_tag="ghcr.io/valhalla/valhalla:3.4.0",
            image_id="sha256:6666666666666666666666666666666666666666666666666666666666666666",
            repo_digests=["ghcr.io/valhalla/valhalla@sha256:666666"],
            oci_title="valhalla",
            oci_revision="3.4.0",
            working_dir="/opt/valhalla",
            compose_service="valhalla",
            git_clean=True,
        )
        HostContainer.objects.create(
            host=get_host("cdn-ses-sandmann-de"),
            container_id="tileserver-01",
            name="tileserver",
            image_tag="maptiler/tileserver-gl-light:v4.8.0",
            image_id="sha256:7777777777777777777777777777777777777777777777777777777777777777",
            repo_digests=["maptiler/tileserver-gl-light@sha256:777777"],
            oci_title="tileserver",
            oci_revision="4.8.0",
            working_dir="/opt/tileserver",
            compose_service="tileserver",
            git_clean=True,
        )

        # 7. Pending apt security updates on 6 hosts
        for slug in (
            "c2-westcode-network",
            "service-westcode-de",
            "remote-westcode-de",
            "monitor-westcode-de",
            "vpn-westcode-de",
            "linkla-ma",
        ):
            host = get_host(slug)
            HostPackage.objects.create(
                host=host,
                name="libssl3t64",
                installed_version="3.0.13-0ubuntu3.1",
                candidate_version="3.0.13-0ubuntu3.4",
                is_security_update=True,
            )
            HostPackage.objects.create(
                host=host,
                name="curl",
                installed_version="8.5.0-2ubuntu10.1",
                candidate_version="8.5.0-2ubuntu10.4",
                is_security_update=True,
            )

        renovate_prs = [
            {
                "service_slug": "plausible",
                "repo_full_name": "westcoder/westcode-infra",
                "file_path": "stacks/hetzner-westcode/files/compose/plausible.yaml",
                "pr_number": 142,
                "pr_url": "https://github.com/westcoder/westcode-infra/pull/142",
                "ci_status": "success",
                "dependency_name": "plausible/analytics",
                "current_version": "2.1.0",
                "target_version": "2.1.2",
            },
            {
                "service_slug": "westcode-hub",
                "repo_full_name": "westcoder/westcode-hub",
                "file_path": "backend/pyproject.toml",
                "pr_number": 88,
                "pr_url": "https://github.com/westcoder/westcode-hub/pull/88",
                "ci_status": "success",
                "dependency_name": "westcode-hub",
                "current_version": "5.2.9",
                "target_version": "5.2.11",
            },
            {
                "service_slug": "postgres",
                "repo_full_name": "westcoder/westcode-infra",
                "file_path": "stacks/hetzner-westcode/files/compose/postgres.yaml",
                "pr_number": 149,
                "pr_url": "https://github.com/westcoder/westcode-infra/pull/149",
                "ci_status": "success",
                "dependency_name": "postgres",
                "current_version": "16.2",
                "target_version": "16.6",
            },
            {
                "service_slug": "coder",
                "repo_full_name": "westcoder/westcode-infra",
                "file_path": "stacks/hetzner-westcode/files/compose/coder.yaml",
                "pr_number": 151,
                "pr_url": "https://github.com/westcoder/westcode-infra/pull/151",
                "ci_status": "success",
                "dependency_name": "coder/coder",
                "current_version": "2.18.0",
                "target_version": "2.18.2",
            },
            {
                "service_slug": "traefik",
                "repo_full_name": "westcoder/westcode-infra",
                "file_path": "stacks/hetzner-westcode/files/compose/traefik.yaml",
                "pr_number": 153,
                "pr_url": "https://github.com/westcoder/westcode-infra/pull/153",
                "ci_status": "success",
                "dependency_name": "traefik",
                "current_version": "3.1.2",
                "target_version": "3.1.4",
            },
            {
                "service_slug": "valhalla",
                "repo_full_name": "westcoder/westcode-infra",
                "file_path": "stacks/hetzner-westcode-tiles/files/compose/valhalla.yaml",
                "pr_number": 155,
                "pr_url": "https://github.com/westcoder/westcode-infra/pull/155",
                "ci_status": "success",
                "dependency_name": "valhalla",
                "current_version": "3.4.0",
                "target_version": "3.5.1",
            },
        ]

        trivy_findings = {
            "plausible:2.1.0": [
                {
                    "VulnerabilityID": "CVE-2026-3104",
                    "Severity": "HIGH",
                    "Status": "fixed",
                    "FixedVersion": "2.1.2",
                    "Title": "Auth-Bypass im Klick-Tracking behoben",
                    "PkgName": "plausible",
                }
            ],
            "westcode-hub:5.2.9": [
                {
                    "VulnerabilityID": "CVE-2026-1892",
                    "Severity": "CRITICAL",
                    "Status": "fixed",
                    "FixedVersion": "5.2.11",
                    "Title": "SQL-Injection in FilteredRelation (Django Security Release)",
                    "PkgName": "django",
                }
            ],
        }

        groups = rebuild_service_groups(
            renovate_prs=renovate_prs,
            trivy_findings=trivy_findings,
            upstream_releases={"tileserver": "4.9.0"},
        )
        self.stdout.write(
            self.style.SUCCESS(f"Seeded {len(groups)} correlated service groups across {Host.objects.count()} hosts.")
        )
