import pytest
from fleet.models import Host, HostContainer, HostPackage
from catalog.correlator import rebuild_service_groups, resolve_container_identity
from catalog.renovate_sync import parse_renovate_pr
from catalog.trivy import filter_actionable_vulns


def test_filter_actionable_vulns_drops_unfixed_and_low():
    raw = [
        {"VulnerabilityID": "CVE-2026-0001", "Severity": "CRITICAL", "Status": "will_not_fix", "FixedVersion": ""},
        {"VulnerabilityID": "CVE-2026-0002", "Severity": "LOW", "Status": "fixed", "FixedVersion": "1.2.3"},
        {"VulnerabilityID": "CVE-2026-3104", "Severity": "HIGH", "Status": "fixed", "FixedVersion": "2.1.2"},
    ]
    filtered = filter_actionable_vulns(raw)
    assert [v["VulnerabilityID"] for v in filtered] == ["CVE-2026-3104"]


@pytest.mark.django_db
def test_resolve_container_identity_maps_retagged_hub_backend():
    host = Host.objects.create(slug="service", hostname="service.westcode.de", provider="hetzner", stack_name="hetzner-westcode-service")
    c = HostContainer.objects.create(
        host=host,
        container_id="c1",
        name="hub-backend-1",
        image_tag="hub-backend",
        image_id="sha256:111",
        repo_digests=["069962555850.dkr.ecr.eu-central-1.amazonaws.com/westcode-hub@sha256:999"],
        oci_title="westcode-hub",
        oci_revision="8f3a1c40",
        working_dir="/opt/hub",
        compose_service="backend",
        status="running",
    )
    slug, name, version = resolve_container_identity(c)
    assert slug == "westcode-hub"
    assert version == "8f3a1c40"

    # Also verify RepoDigests fallback when oci_title is empty
    c_no_oci = HostContainer.objects.create(
        host=host,
        container_id="c2",
        name="hub-worker-1",
        image_tag="hub-worker",
        image_id="sha256:222",
        repo_digests=["069962555850.dkr.ecr.eu-central-1.amazonaws.com/westcode-hub@sha256:abc1234"],
        oci_title="",
        oci_revision="",
        working_dir="/opt/hub",
        compose_service="worker",
        status="running",
    )
    slug2, _, version2 = resolve_container_identity(c_no_oci)
    assert slug2 == "westcode-hub"
    assert version2 == "sha256:abc1234"


@pytest.mark.django_db
def test_rebuild_service_groups_aggregates_plausible_across_git_and_three_hosts():
    for slug, ver in [("c2", "v2.1.0"), ("wew-homepage", "v2.1.0"), ("masteroil", "v2.0.4")]:
        h = Host.objects.create(slug=slug, hostname=f"{slug}.westcode.de", provider="hetzner", stack_name=f"hetzner-{slug}")
        HostContainer.objects.create(
            host=h,
            container_id=f"cid-{slug}",
            name="plausible-1",
            image_tag=f"plausible/analytics:{ver}",
            image_id=f"sha256:{slug}",
            repo_digests=[f"plausible/analytics@sha256:{slug}"],
            working_dir="/opt/plausible",
            compose_service="plausible",
            git_clean=True,
            status="running",
        )

    groups = rebuild_service_groups(
        renovate_prs=[
            {
                "service_slug": "plausible",
                "repo_full_name": "westcoder/westcode-web",
                "file_path": "deploy/compose.yaml",
                "pr_number": 142,
                "pr_url": "https://github.com/westcoder/westcode-web/pull/142",
                "ci_status": "success",
                "target_version": "2.1.2",
            }
        ],
        trivy_findings={
            "plausible": [
                {"VulnerabilityID": "CVE-2026-3104", "Severity": "HIGH", "Status": "fixed", "FixedVersion": "2.1.2", "Title": "Auth-Bypass im Klick-Tracking behoben"}
            ]
        },
        upstream_releases={"plausible": "2.1.2"},
    )
    plausible = next(g for g in groups if g.slug == "plausible")
    assert plausible.category == "action_required"
    assert plausible.highest_cve_id == "CVE-2026-3104"
    assert plausible.git_targets.count() == 1
    assert plausible.host_targets.count() == 3


@pytest.mark.django_db
def test_rebuild_service_groups_excludes_dead_ecr_tags_and_builds_apt_and_eol_groups():
    host = Host.objects.create(
        slug="linklama",
        hostname="linklama.westcode.de",
        provider="hetzner",
        stack_name="hetzner-linklama",
        os_distro="ubuntu",
        os_version="20.04",
        is_os_eol=True,
    )
    HostPackage.objects.create(
        host=host,
        name="libssl1.1",
        installed_version="1.1.1f-1ubuntu2.20",
        candidate_version="1.1.1f-1ubuntu2.22",
        is_security_update=True,
    )
    HostContainer.objects.create(
        host=host,
        container_id="c-hub",
        name="hub-backend-1",
        image_tag="hub-backend",
        image_id="sha256:active",
        repo_digests=["069962555850.dkr.ecr.eu-central-1.amazonaws.com/westcode-hub@sha256:active"],
        oci_title="westcode-hub",
        oci_revision="8f3a1c40",
        working_dir="/opt/hub",
        compose_service="backend",
        status="running",
    )

    groups = rebuild_service_groups(
        renovate_prs=[],
        trivy_findings={
            # Historical ECR image tag in keep_10 history not running on any VM and with no open PR
            "069962555850.dkr.ecr.eu-central-1.amazonaws.com/westcode-crm:old-sha-deadbeef": [
                {
                    "VulnerabilityID": "CVE-2026-9999",
                    "Severity": "CRITICAL",
                    "Status": "fixed",
                    "FixedVersion": "3.0.1",
                    "Title": "Old unused ECR image vulnerability",
                }
            ],
            "westcode-legacy-unused": [
                {
                    "VulnerabilityID": "CVE-2026-9998",
                    "Severity": "HIGH",
                    "Status": "fixed",
                    "FixedVersion": "1.0.1",
                    "Title": "Unused service finding",
                }
            ],
            # Historical tag of an active repo that is NOT the running revision (8f3a1c40)
            "westcode-hub:1111dead": [
                {
                    "VulnerabilityID": "CVE-2026-8888",
                    "Severity": "CRITICAL",
                    "Status": "fixed",
                    "FixedVersion": "9.9.9",
                    "Title": "Stale tag on active repo",
                }
            ],
        },
        upstream_releases={"westcode-legacy-unused": "1.0.1"},
    )

    slugs = {g.slug for g in groups}
    assert "westcode-crm" not in slugs
    assert "westcode-legacy-unused" not in slugs
    assert "westcode-hub" not in slugs
    assert "ubuntu-apt" in slugs
    assert "ubuntu-eol" in slugs

    apt_group = next(g for g in groups if g.slug == "ubuntu-apt")
    assert apt_group.category == "action_required"
    assert apt_group.host_targets.count() == 1
    assert apt_group.host_targets.first().target_type == "apt"

    eol_group = next(g for g in groups if g.slug == "ubuntu-eol")
    assert eol_group.category == "action_required"
    assert eol_group.host_targets.count() == 1
    assert eol_group.host_targets.first().target_type == "os_eol"


def test_parse_renovate_pr_normalizes_dependency_and_version():
    parsed = parse_renovate_pr(
        {
            "number": 142,
            "title": "chore(deps): update docker image plausible/analytics to v2.1.2",
            "html_url": "https://github.com/westcoder/westcode-web/pull/142",
        },
        repo_full_name="westcoder/westcode-web",
        file_path="deploy/compose.yaml",
        ci_status="success",
    )
    assert parsed == {
        "service_slug": "plausible",
        "repo_full_name": "westcoder/westcode-web",
        "file_path": "deploy/compose.yaml",
        "pr_number": 142,
        "pr_url": "https://github.com/westcoder/westcode-web/pull/142",
        "ci_status": "success",
        "target_version": "2.1.2",
    }

