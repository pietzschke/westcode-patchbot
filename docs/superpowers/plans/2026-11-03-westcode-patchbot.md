# Westcode Patchbot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `westcode-patchbot`, a standalone fleet indexing, CVE/update correlation, and serial canary rollout system for Westcode's 23 VMs and 37 ECR repositories.

**Architecture:** A Django 5.2 + DRF control plane (`backend/`) ingests host package/container inventories from a stdlib-only Python pull agent (`agent/patchbot_agent.py`), correlates them with `westcode-infra` server definitions, Trivy SBOM/CVE scans, and Renovate GitHub PRs, and serves an Angular 22 Master-Detail UI (`frontend/`) styled after Westcode's design system. Updates execute either via GitHub PR merge / CircleCI trigger (for Git-owned services) or via a 2-step `tofu plan`-style pre-check and serial canary rollout with automatic healthcheck rollback (for host-local `/opt/...` services and `apt`).

**Tech Stack:** Python 3.13 (`uv`), Django 5.2, Django REST Framework 3.16, PostgreSQL 18, pytest, stdlib Python 3.8+ (host agent), Angular 22, Vitest, Trivy Server, Renovate.

**Spec:** [`docs/superpowers/specs/2026-11-03-westcode-patchbot-design.md`](file:///Users/pietzschke/projects/westcode-patchbot/docs/superpowers/specs/2026-11-03-westcode-patchbot-design.md)

## Global Constraints

- **Customer VM Isolation:** Host tokens are bound 1:1 to a single `Host.hostname`; a token for host A must never read or mutate host B or global state.
- **Pull-Only Agent:** The host agent initiates outbound HTTPS requests only; no inbound ports or central SSH keys are added to customer VMs.
- **No Git Drift:** Services backed by a GitHub repository and CircleCI pipeline are updated exclusively by merging their PR / triggering CI, never by mutating `/opt/...` on the VM directly.
- **Agent Compatibility:** `agent/patchbot_agent.py` uses Python 3.8+ standard library modules only (no third-party `pip` packages) so it runs unmodified on legacy `ubuntu-20.04` hosts through `debian-13`.
- **Path & Command Safety:** The host agent accepts only fixed action types (`precheck`, `compose_update`, `apt_upgrade`, `host_reboot`) and validates all `working_dir` paths to be canonical subdirectories of `/opt/`.
- **Noise Filtering:** Unfixed CVEs (`status != "fixed"`), `LOW`/`UNKNOWN` severities, and ECR image tags not currently running on any VM (or `main`/`develop` head) are excluded from active service groups and alerts by default.
- **Westcode UI Rules (`DESIGN.md`):** Pure white ground (`#ffffff`), cut surfaces (`12px` 45° corner on `#f5f5f7`), Aeonik weights `400` and `700` only, `tabular-nums` on all numbers, and **The One Voice Rule** (at most one `Bluefly 400` `#5a61fb` primary button visible on screen).

## Review Focus

1. **Locally re-tagged ECR images (`hub-backend` on `service.westcode.de`):** When a deploy script runs `docker tag <ecr>/westcode-hub:<sha> hub-backend`, correlation must match the running container back to the `westcode-hub` ECR repository and GitHub repo using `RepoDigests` (`sha256:...`) or OCI labels (`org.opencontainers.image.title`), never failing because the local image name lacks an ECR prefix (tested in Task 4).
2. **Legacy `image = null` and ephemeral `westcode-tiles` stacks in `westcode-infra`:** Parsing `stacks/hetzner-*/servers.tf` must include the three legacy servers with `image = null` (`brockhaus-hydrogen`, `masteroil`, `unternehmerrat-hagen`) as required hosts while excluding `hetzner-westcode-tiles` build servers (tested in Task 1).
3. **Dirty `/opt/...` git repository or path traversal on host rollout:** If `/opt/plausible` has uncommitted manual edits (`git status --porcelain` non-empty) or a job payload supplies `working_dir="/opt/../etc"`, `precheck` and `compose_update` must refuse execution before touching Docker (tested in Task 2).
4. **Canary failure on Host 1 during multi-host rollout:** When a 3-host Plausible rollout fails the 60s healthcheck on Host 1, the agent rolls Host 1 back to `prev_image_id` and the control plane immediately aborts the pending jobs for Hosts 2 and 3 (tested in Task 2 and Task 5).
5. **Cross-host token spoofing & duplicate Zammad tickets:** A compromised customer VM presenting its bearer token with another host's hostname must receive `403 Forbidden` (tested in Task 3), and repeated Trivy scans finding the same `CVE-2026-3104` on `plausible` must open only one Zammad ticket via fingerprint deduplication (tested in Task 6).

---

### File Map

```text
westcode-patchbot/
├── agent/
│   ├── patchbot_agent.py              # Stdlib-only systemd pull agent (inventory + precheck + rollout/rollback)
│   └── tests/
│       └── test_agent.py              # Unit tests for inventory, path guard, git check, canary rollback
├── backend/
│   ├── pyproject.toml                 # uv config, Django 5.2, DRF, pytest
│   ├── manage.py
│   ├── config/
│   │   ├── settings.py
│   │   ├── settings_test.py
│   │   └── urls.py
│   ├── fleet/
│   │   ├── models.py                  # Host, HostPackage, HostContainer, AgentJob
│   │   ├── infra_sync.py              # Parses westcode-infra stacks/*/servers.tf & server.tf
│   │   ├── auth.py                    # HostTokenAuthentication (1:1 host-scoped bearer token)
│   │   ├── api.py                     # Agent report, job polling, job result views
│   │   └── tests/
│   │       ├── test_infra_sync.py
│   │       └── test_agent_api.py
│   ├── catalog/
│   │   ├── models.py                  # ServiceGroup, GitTarget, HostTarget, VulnerabilityFinding
│   │   ├── correlator.py              # Matches RepoDigests/OCI labels, filters unfixed/dead tags, groups by service
│   │   ├── trivy.py                   # Trivy SBOM/package scan client + noise filter
│   │   ├── renovate_sync.py           # Syncs open Renovate PRs + CI status from GitHub API
│   │   └── tests/
│   │       └── test_correlator.py
│   ├── rollouts/
│   │   ├── models.py                  # RolloutPlan, RolloutStep
│   │   ├── orchestrator.py            # 2-step plan builder + serial canary state machine
│   │   ├── api.py                     # Service list, plan preview, plan execute endpoints
│   │   └── tests/
│   │       └── test_orchestrator.py
│   └── alerts/
│       ├── models.py                  # AlertFingerprint, NotificationRule
│       ├── router.py                  # Slack webhook, Zammad API client, weekly owner email digest
│       └── tests/
│           └── test_router.py
├── frontend/
│   ├── package.json
│   └── src/app/
│       ├── core/
│       │   ├── patchbot-api.ts        # Typed HTTP client for services, plans, hosts
│       │   └── logos.ts               # SVG logo registry + Westcode monogram fallback
│       └── pages/
│           ├── services-page.ts       # Master-Detail "Nach Dienst" view + One-Voice Plan panel
│           ├── services-page.spec.ts
│           └── hosts-page.ts          # 23 VMs overview + EOL & heartbeat warnings
└── deploy/
    ├── compose.yaml                   # Production compose (backend, db, trivy, renovate-runner)
    ├── westcode-patchbot-agent.service
    └── install-agent.sh
```

---

### Task 1: Backend Foundation, Fleet Models & `westcode-infra` Target Sync

**Files:**
- Create: `backend/pyproject.toml`
- Create: `backend/manage.py`
- Create: `backend/config/__init__.py`
- Create: `backend/config/settings.py`
- Create: `backend/config/settings_test.py`
- Create: `backend/config/urls.py`
- Create: `backend/fleet/__init__.py`
- Create: `backend/fleet/models.py`
- Create: `backend/fleet/infra_sync.py`
- Test: `backend/fleet/tests/test_infra_sync.py`

**Interfaces:**
- Produces:
  - `fleet.models.Host`: fields `slug: str`, `hostname: str`, `provider: str` (`"hetzner"` | `"ionos"`), `stack_name: str`, `declared_image: str | None`, `os_distro: str`, `os_version: str`, `is_os_eol: bool`, `reboot_required: bool`, `agent_token_hash: str`, `last_seen_at: datetime | None`
  - `fleet.models.HostPackage`: fields `host: ForeignKey(Host)`, `name: str`, `installed_version: str`, `candidate_version: str`, `is_security_update: bool`
  - `fleet.models.HostContainer`: fields `host: ForeignKey(Host)`, `container_id: str`, `name: str`, `image_tag: str`, `image_id: str`, `repo_digests: list[str]`, `oci_title: str`, `oci_revision: str`, `working_dir: str`, `compose_service: str`, `git_clean: bool | None`, `status: str`
  - `fleet.infra_sync.sync_infra_hosts(infra_root: Path) -> list[Host]`
  - `fleet.infra_sync.is_distro_eol(distro: str, version: str, today: date) -> bool`

- [ ] **Step 1: Initialize Git repository, `backend/pyproject.toml`, and minimal Django test settings**

Run `git init` in `/Users/pietzschke/projects/westcode-patchbot`, add `.gitignore` (ignoring `.venv/`, `__pycache__/`, `node_modules/`, `.superpowers/`), and create `backend/pyproject.toml` with `django>=5.2,<6`, `djangorestframework>=3.16`, `psycopg[binary]>=3.2`, `requests>=2.32`, `pytest>=8`, `pytest-django>=4.9`.

- [ ] **Step 2: Write the failing tests for `westcode-infra` parsing and EOL detection in `backend/fleet/tests/test_infra_sync.py`**

```python
from datetime import date
from pathlib import Path
import pytest
from fleet.infra_sync import is_distro_eol, sync_infra_hosts
from fleet.models import Host


@pytest.mark.django_db
def test_sync_infra_hosts_parses_real_westcode_infra():
    infra_path = Path("/Users/pietzschke/projects/westcode-infra")
    hosts = sync_infra_hosts(infra_path)
    stack_names = {h.stack_name for h in hosts}

    assert len(hosts) == 23
    assert "hetzner-westcode-tiles" not in stack_names
    assert "ionos-westcode" in stack_names

    linklama = Host.objects.get(stack_name="hetzner-linklama")
    assert linklama.declared_image == "ubuntu-20.04"
    assert linklama.is_os_eol is True

    masteroil = Host.objects.get(stack_name="hetzner-masteroil")
    assert masteroil.declared_image is None


def test_is_distro_eol_flags_ubuntu_20_04():
    assert is_distro_eol("ubuntu", "20.04", today=date(2026, 11, 3)) is True
    assert is_distro_eol("ubuntu", "24.04", today=date(2026, 11, 3)) is False
    assert is_distro_eol("debian", "13", today=date(2026, 11, 3)) is False
```

- [ ] **Step 3: Run pytest to verify the test fails**

Run: `cd backend && uv run pytest fleet/tests/test_infra_sync.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'fleet.infra_sync'`)

- [ ] **Step 4: Implement `fleet/models.py` and `fleet/infra_sync.py`**

Implement `Host`, `HostPackage`, `HostContainer`, and `AgentJob` models in `backend/fleet/models.py` (run `makemigrations fleet`), and implement `sync_infra_hosts(infra_root: Path) -> list[Host]` in `backend/fleet/infra_sync.py` by parsing `resource "hcloud_server"` blocks in `stacks/hetzner-*/servers.tf` and `resource "ionoscloud_cube_server"` in `stacks/ionos-westcode/server.tf`, skipping `hetzner-westcode-tiles`.

- [ ] **Step 5: Run pytest to verify the tests pass**

Run: `cd backend && uv run pytest fleet/tests/test_infra_sync.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit Task 1**

```bash
git add .gitignore backend/
git commit -m "feat(fleet): add host inventory models and westcode-infra stack sync"
```

---

### Task 2: Stdlib-Only Host Agent (`agent/patchbot_agent.py`) – Inventory, Pre-Check & Rollback

**Files:**
- Create: `agent/patchbot_agent.py`
- Test: `agent/tests/test_agent.py`

**Interfaces:**
- Produces:
  - `validate_opt_workdir(working_dir: str, allowed_root: Path = Path("/opt")) -> Path` (raises `ValueError` if not a canonical subdirectory inside `allowed_root`)
  - `parse_apt_simulation(sim_output: str) -> list[dict]` (returns `[{"name": str, "installed_version": str, "candidate_version": str, "is_security_update": bool}]` from `apt-get -s dist-upgrade` `Inst` lines)
  - `run_precheck(working_dir: str, target_image: str, runner: Callable, allowed_root: Path = Path("/opt")) -> dict` (returns `{"ok": bool, "git_clean": bool, "compose_file": str, "reason": str}`)
  - `execute_compose_update(working_dir: str, service: str, target_image: str, healthcheck_url: str | None, runner: Callable, allowed_root: Path = Path("/opt"), timeout_sec: int = 60) -> dict` (returns `{"status": "succeeded" | "rolled_back" | "failed", "prev_image_id": str, "new_image_id": str, "logs": str}`)

- [ ] **Step 1: Write the failing unit tests in `agent/tests/test_agent.py`**

```python
from pathlib import Path
import pytest
from agent.patchbot_agent import (
    execute_compose_update,
    parse_apt_simulation,
    run_precheck,
    validate_opt_workdir,
)


def test_validate_opt_workdir_rejects_traversal(tmp_path):
    opt = tmp_path / "opt"
    (opt / "plausible").mkdir(parents=True)
    assert validate_opt_workdir(str(opt / "plausible"), allowed_root=opt) == (opt / "plausible").resolve()

    with pytest.raises(ValueError, match="outside allowed root"):
        validate_opt_workdir(str(opt / "../etc"), allowed_root=opt)


def test_parse_apt_simulation_distinguishes_security_pocket():
    sample = (
        "Inst libssl3t64 [3.0.11-1] (3.0.14-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"
        "Inst curl [7.88.1-10] (7.88.1-10+deb12u5 Debian:12.6/stable [amd64])\n"
    )
    pkgs = parse_apt_simulation(sample)
    assert pkgs == [
        {
            "name": "libssl3t64",
            "installed_version": "3.0.11-1",
            "candidate_version": "3.0.14-1~deb12u1",
            "is_security_update": True,
        },
        {
            "name": "curl",
            "installed_version": "7.88.1-10",
            "candidate_version": "7.88.1-10+deb12u5",
            "is_security_update": False,
        },
    ]


def test_run_precheck_blocks_dirty_git_tree(tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    (svc / "compose.yaml").write_text("services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n")

    def dirty_runner(cmd, cwd=None):
        if cmd[:2] == ["git", "status"]:
            return (0, " M compose.yaml\n", "")
        return (0, "", "")

    res = run_precheck(str(svc), "plausible/analytics:v2.1.2", runner=dirty_runner, allowed_root=opt)
    assert res["ok"] is False
    assert res["git_clean"] is False
    assert "uncommitted" in res["reason"]


def test_execute_compose_update_rolls_back_on_failed_healthcheck(tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    compose_file = svc / "compose.yaml"
    compose_file.write_text("services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n")
    calls = []

    def fake_runner(cmd, cwd=None):
        calls.append(cmd)
        if cmd[:3] == ["docker", "compose", "images"]:
            return (0, "sha256:old111\n", "")
        if cmd[:3] == ["docker", "compose", "logs"]:
            return (0, "DB migration failed\n", "")
        return (0, "", "")

    result = execute_compose_update(
        working_dir=str(svc),
        service="plausible",
        target_image="plausible/analytics:v2.1.2",
        healthcheck_url="http://127.0.0.1:59999/api/health",
        runner=fake_runner,
        allowed_root=opt,
        timeout_sec=1,
    )
    assert result["status"] == "rolled_back"
    assert result["prev_image_id"] == "sha256:old111"
    assert "plausible/analytics:v2.1.0" in compose_file.read_text()
    assert "DB migration failed" in result["logs"]
```

- [ ] **Step 2: Run pytest on `agent/tests/test_agent.py` to verify it fails**

Run: `cd backend && PYTHONPATH=.. uv run pytest ../agent/tests/test_agent.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'agent'`)

- [ ] **Step 3: Implement `agent/patchbot_agent.py` using only Python standard library modules**

Implement `validate_opt_workdir`, `parse_apt_simulation`, `collect_host_inventory`, `run_precheck`, and `execute_compose_update` (recording original `compose.yaml` content and `prev_image_id` before update, polling `healthcheck_url` or container health state, and restoring `compose.yaml` + running `docker compose up -d --remove-orphans` on failure).

- [ ] **Step 4: Run pytest to verify all agent tests pass**

Run: `cd backend && PYTHONPATH=.. uv run pytest ../agent/tests/test_agent.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit Task 2**

```bash
git add agent/
git commit -m "feat(agent): add stdlib pull agent with /opt path guard and canary rollback"
```

---

### Task 3: Agent API & Per-Host Token Isolation (`backend/fleet/api.py`)

**Files:**
- Create: `backend/fleet/auth.py`
- Create: `backend/fleet/api.py`
- Modify: `backend/config/urls.py`
- Test: `backend/fleet/tests/test_agent_api.py`

**Interfaces:**
- Consumes: `fleet.models.{Host, HostPackage, HostContainer, AgentJob}`
- Produces:
  - `fleet.auth.HostTokenAuthentication`: authenticates `Authorization: Bearer <token>` against `hashlib.sha256(token).hexdigest() == Host.agent_token_hash` and sets `request.auth = host`
  - `POST /api/agent/report/`: updates `request.auth` (`Host`) packages, containers, `os_distro`, `os_version`, `is_os_eol`, `reboot_required`, and `last_seen_at`; rejects payload if `payload["hostname"] != request.auth.hostname` with `403`
  - `GET /api/agent/jobs/next/`: returns the oldest `PENDING` `AgentJob` for `request.auth` only and marks it `DISPATCHED`
  - `POST /api/agent/jobs/<uuid:job_id>/result/`: records `status` (`SUCCEEDED` | `ROLLED_BACK` | `FAILED`) and `result_payload` if and only if `job.host == request.auth`

- [ ] **Step 1: Write the failing API & isolation tests in `backend/fleet/tests/test_agent_api.py`**

```python
import hashlib
import pytest
from rest_framework.test import APIClient
from fleet.models import AgentJob, Host


@pytest.fixture
def hosts(db):
    t1 = "tok-linklama-secret"
    t2 = "tok-masteroil-secret"
    h1 = Host.objects.create(
        slug="linklama",
        hostname="linklama.westcode.de",
        provider="hetzner",
        stack_name="hetzner-linklama",
        agent_token_hash=hashlib.sha256(t1.encode()).hexdigest(),
    )
    h2 = Host.objects.create(
        slug="masteroil",
        hostname="masteroil.westcode.de",
        provider="hetzner",
        stack_name="hetzner-masteroil",
        agent_token_hash=hashlib.sha256(t2.encode()).hexdigest(),
    )
    return (h1, t1, h2, t2)


@pytest.mark.django_db
def test_agent_report_rejects_cross_host_spoofing(hosts):
    h1, t1, h2, _ = hosts
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {t1}")

    resp = client.post(
        "/api/agent/report/",
        data={"hostname": "masteroil.westcode.de", "os_distro": "ubuntu", "os_version": "24.04", "packages": [], "containers": []},
        format="json",
    )
    assert resp.status_code == 403


@pytest.mark.django_db
def test_agent_report_persists_packages_and_containers(hosts):
    h1, t1, _, _ = hosts
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {t1}")

    resp = client.post(
        "/api/agent/report/",
        data={
            "hostname": "linklama.westcode.de",
            "os_distro": "ubuntu",
            "os_version": "20.04",
            "reboot_required": True,
            "packages": [
                {"name": "openssl", "installed_version": "1.1.1f", "candidate_version": "1.1.1f-2", "is_security_update": True}
            ],
            "containers": [
                {
                    "container_id": "c1",
                    "name": "hub-backend-1",
                    "image_tag": "hub-backend",
                    "image_id": "sha256:abc",
                    "repo_digests": ["069962555850.dkr.ecr.eu-central-1.amazonaws.com/westcode-hub@sha256:deadbeef"],
                    "oci_title": "westcode-hub",
                    "oci_revision": "8f3a1c",
                    "working_dir": "/opt/hub",
                    "compose_service": "backend",
                    "git_clean": True,
                    "status": "running",
                }
            ],
        },
        format="json",
    )
    assert resp.status_code == 200
    h1.refresh_from_db()
    assert h1.is_os_eol is True
    assert h1.reboot_required is True
    assert h1.packages.count() == 1
    assert h1.containers.get().oci_title == "westcode-hub"
```

- [ ] **Step 2: Run pytest to verify the tests fail**

Run: `cd backend && uv run pytest fleet/tests/test_agent_api.py -v`
Expected: FAIL (`404 Not Found` / missing `fleet.auth`)

- [ ] **Step 3: Implement `backend/fleet/auth.py`, `backend/fleet/api.py`, and wire URLs in `backend/config/urls.py`**

Implement `HostTokenAuthentication` and the three views (`AgentReportView`, `AgentNextJobView`, `AgentJobResultView`).

- [ ] **Step 4: Run pytest to verify the tests pass**

Run: `cd backend && uv run pytest fleet/tests/test_agent_api.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit Task 3**

```bash
git add backend/fleet/ backend/config/urls.py
git commit -m "feat(fleet): add host-scoped token auth and agent inventory/job endpoints"
```

---

### Task 4: Correlation Engine, Trivy Filter & Service Grouping (`backend/catalog/`)

**Files:**
- Create: `backend/catalog/__init__.py`
- Create: `backend/catalog/models.py`
- Create: `backend/catalog/trivy.py`
- Create: `backend/catalog/correlator.py`
- Test: `backend/catalog/tests/test_correlator.py`

**Interfaces:**
- Consumes: `fleet.models.{Host, HostPackage, HostContainer}`
- Produces:
  - `catalog.models.ServiceGroup`: fields `slug: str`, `display_name: str`, `logo_key: str`, `category: str` (`"action_required"` | `"ready_to_rollout"`), `current_version_summary: str`, `target_version: str`, `highest_cve_id: str`, `highest_severity: str`, `summary_line: str`
  - `catalog.models.GitTarget`: fields `service_group: ForeignKey(ServiceGroup)`, `repo_full_name: str`, `file_path: str`, `pr_number: int | None`, `pr_url: str`, `ci_status: str`, `target_version: str`
  - `catalog.models.HostTarget`: fields `service_group: ForeignKey(ServiceGroup)`, `host: ForeignKey(Host)`, `target_type: str` (`"compose"` | `"ecr_app"` | `"apt"` | `"os_eol"`), `working_dir: str`, `compose_service: str`, `running_version: str`, `target_version: str`, `git_clean: bool | None`
  - `catalog.trivy.filter_actionable_vulns(raw_vulns: list[dict]) -> list[dict]` (keeps only `Status == "fixed"` and `Severity in {"CRITICAL", "HIGH", "MEDIUM"}`)
  - `catalog.correlator.resolve_container_identity(container: HostContainer) -> tuple[str, str, str]` (returns `(service_slug, display_name, running_version)` using `repo_digests` and `oci_title` so locally re-tagged `hub-backend` resolves to `westcode-hub`)
  - `catalog.correlator.rebuild_service_groups(renovate_prs: list[dict], trivy_findings: dict[str, list[dict]], upstream_releases: dict[str, str]) -> list[ServiceGroup]`

- [ ] **Step 1: Write the failing correlation & noise-filtering tests in `backend/catalog/tests/test_correlator.py`**

```python
import pytest
from fleet.models import Host, HostContainer
from catalog.correlator import rebuild_service_groups, resolve_container_identity
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
```

- [ ] **Step 2: Run pytest to verify the tests fail**

Run: `cd backend && uv run pytest catalog/tests/test_correlator.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'catalog'`)

- [ ] **Step 3: Implement `catalog/models.py`, `catalog/trivy.py`, and `catalog/correlator.py`**

Create models (`ServiceGroup`, `GitTarget`, `HostTarget`), register `"catalog"` in `INSTALLED_APPS`, generate migrations, and implement `filter_actionable_vulns`, `resolve_container_identity`, and `rebuild_service_groups` (including automatic generation of the `ubuntu-apt` and `ubuntu-eol` service groups from `Host` / `HostPackage`).

- [ ] **Step 4: Run pytest to verify the tests pass**

Run: `cd backend && uv run pytest catalog/tests/test_correlator.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit Task 4**

```bash
git add backend/catalog/ backend/config/settings.py
git commit -m "feat(catalog): add service-centric correlation engine and Trivy noise filter"
```

---

### Task 5: Two-Step Rollout Planner & Serial Canary Orchestrator (`backend/rollouts/`)

**Files:**
- Create: `backend/rollouts/__init__.py`
- Create: `backend/rollouts/models.py`
- Create: `backend/rollouts/orchestrator.py`
- Create: `backend/rollouts/api.py`
- Modify: `backend/config/urls.py`
- Test: `backend/rollouts/tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `catalog.models.{ServiceGroup, GitTarget, HostTarget}`, `fleet.models.{Host, AgentJob}`
- Produces:
  - `rollouts.models.RolloutPlan`: fields `id: UUID`, `service_group: ForeignKey(ServiceGroup)`, `status: str` (`"READY"` | `"BLOCKED"` | `"RUNNING"` | `"SUCCEEDED"` | `"ROLLED_BACK"`), `block_reason: str`
  - `rollouts.models.RolloutStep`: fields `plan: ForeignKey(RolloutPlan)`, `order: int`, `step_type: str` (`"github_merge"` | `"host_compose"` | `"host_apt"`), `host: ForeignKey(Host, null=True)`, `git_target: ForeignKey(GitTarget, null=True)`, `agent_job: OneToOneField(AgentJob, null=True)`, `status: str` (`"PENDING"` | `"RUNNING"` | `"SUCCEEDED"` | `"ROLLED_BACK"` | `"ABORTED"`)
  - `rollouts.orchestrator.create_rollout_plan(service_group: ServiceGroup) -> RolloutPlan` (marks plan `BLOCKED` if any target `/opt` host has `git_clean is False`)
  - `rollouts.orchestrator.start_rollout_plan(plan: RolloutPlan, github_merger: Callable) -> RolloutPlan` (executes `github_merge` steps via `github_merger`, and dispatches **only the first** `host_compose`/`host_apt` step as an `AgentJob`, keeping subsequent host steps in `PENDING`)
  - `rollouts.orchestrator.advance_rollout_on_job_result(job: AgentJob) -> RolloutPlan` (when `job.status == "SUCCEEDED"`, dispatches the next `PENDING` host step; when `job.status in {"ROLLED_BACK", "FAILED"}`, marks all remaining `PENDING` steps `ABORTED` and sets `plan.status = "ROLLED_BACK"`)

- [ ] **Step 1: Write the failing canary orchestration tests in `backend/rollouts/tests/test_orchestrator.py`**

```python
import pytest
from fleet.models import AgentJob, Host
from catalog.models import GitTarget, HostTarget, ServiceGroup
from rollouts.orchestrator import (
    advance_rollout_on_job_result,
    create_rollout_plan,
    start_rollout_plan,
)


@pytest.fixture
def plausible_group(db):
    sg = ServiceGroup.objects.create(
        slug="plausible",
        display_name="Plausible Analytics",
        logo_key="plausible",
        category="action_required",
        current_version_summary="2.1.0",
        target_version="2.1.2",
        highest_cve_id="CVE-2026-3104",
        highest_severity="HIGH",
    )
    GitTarget.objects.create(
        service_group=sg,
        repo_full_name="westcoder/westcode-web",
        file_path="deploy/compose.yaml",
        pr_number=142,
        pr_url="https://github.com/westcoder/westcode-web/pull/142",
        ci_status="success",
        target_version="2.1.2",
    )
    for slug in ["c2", "wew-homepage", "masteroil"]:
        h = Host.objects.create(slug=slug, hostname=f"{slug}.westcode.de", provider="hetzner", stack_name=f"hetzner-{slug}")
        HostTarget.objects.create(
            service_group=sg,
            host=h,
            target_type="compose",
            working_dir="/opt/plausible",
            compose_service="plausible",
            running_version="2.1.0",
            target_version="2.1.2",
            git_clean=True,
        )
    return sg


@pytest.mark.django_db
def test_serial_canary_dispatches_host_1_then_aborts_rest_on_rollback(plausible_group):
    merged_prs = []
    plan = create_rollout_plan(plausible_group)
    assert plan.status == "READY"

    start_rollout_plan(plan, github_merger=lambda repo, pr: merged_prs.append((repo, pr)))
    assert merged_prs == [("westcoder/westcode-web", 142)]

    host_steps = list(plan.steps.filter(step_type="host_compose").order_by("order"))
    assert host_steps[0].status == "RUNNING"
    assert host_steps[0].agent_job is not None
    assert host_steps[1].status == "PENDING"
    assert host_steps[2].status == "PENDING"

    job1 = host_steps[0].agent_job
    job1.status = "ROLLED_BACK"
    job1.result_payload = {"logs": "Healthcheck HTTP 502"}
    job1.save()

    plan = advance_rollout_on_job_result(job1)
    assert plan.status == "ROLLED_BACK"
    for s in host_steps[1:]:
        s.refresh_from_db()
        assert s.status == "ABORTED"
        assert s.agent_job is None


@pytest.mark.django_db
def test_create_rollout_plan_blocks_when_opt_git_is_dirty(plausible_group):
    ht = plausible_group.host_targets.first()
    ht.git_clean = False
    ht.save()

    plan = create_rollout_plan(plausible_group)
    assert plan.status == "BLOCKED"
    assert ht.host.hostname in plan.block_reason
```

- [ ] **Step 2: Run pytest to verify the tests fail**

Run: `cd backend && uv run pytest rollouts/tests/test_orchestrator.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'rollouts'`)

- [ ] **Step 3: Implement `rollouts/models.py`, `rollouts/orchestrator.py`, and `rollouts/api.py`**

Implement `RolloutPlan`, `RolloutStep`, the serial canary state machine in `orchestrator.py`, and REST views in `rollouts/api.py` (`GET /api/services/`, `POST /api/services/<slug>/plan/`, `POST /api/plans/<uuid:plan_id>/execute/`, `GET /api/hosts/`). Wire `advance_rollout_on_job_result` into `AgentJobResultView`.

- [ ] **Step 4: Run pytest to verify the tests pass**

Run: `cd backend && uv run pytest rollouts/tests/test_orchestrator.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit Task 5**

```bash
git add backend/rollouts/ backend/fleet/api.py backend/config/
git commit -m "feat(rollouts): add two-step rollout planner and serial canary orchestrator"
```

---

### Task 6: Notification Router – Slack, Zammad API & Owner Digest (`backend/alerts/`)

**Files:**
- Create: `backend/alerts/__init__.py`
- Create: `backend/alerts/models.py`
- Create: `backend/alerts/router.py`
- Test: `backend/alerts/tests/test_router.py`

**Interfaces:**
- Consumes: `catalog.models.ServiceGroup`, `rollouts.models.RolloutPlan`
- Produces:
  - `alerts.models.AlertFingerprint`: fields `fingerprint: str` (unique), `channel: str`, `external_ref: str` (e.g. Zammad ticket ID), `created_at: datetime`
  - `alerts.router.notify_critical_cve(service_group: ServiceGroup, transport: AlertTransport) -> bool` (sends Slack message + creates Zammad ticket once per `f"cve:{service_group.slug}:{service_group.highest_cve_id}"` fingerprint; returns `False` if already sent)
  - `alerts.router.notify_rollout_rollback(plan: RolloutPlan, logs: str, transport: AlertTransport) -> bool`
  - `alerts.router.build_weekly_digest(groups: Iterable[ServiceGroup], hosts: Iterable[Host]) -> dict`

- [ ] **Step 1: Write the failing deduplication & routing tests in `backend/alerts/tests/test_router.py`**

```python
import pytest
from catalog.models import ServiceGroup
from alerts.router import notify_critical_cve


class FakeTransport:
    def __init__(self):
        self.slack_messages = []
        self.zammad_tickets = []

    def send_slack(self, text: str):
        self.slack_messages.append(text)

    def create_zammad_ticket(self, title: str, body: str, group: str = "Infra") -> str:
        self.zammad_tickets.append((title, body, group))
        return f"ZMD-{len(self.zammad_tickets)}"


@pytest.mark.django_db
def test_notify_critical_cve_deduplicates_zammad_and_slack():
    sg = ServiceGroup.objects.create(
        slug="plausible",
        display_name="Plausible Analytics",
        logo_key="plausible",
        category="action_required",
        current_version_summary="2.1.0",
        target_version="2.1.2",
        highest_cve_id="CVE-2026-3104",
        highest_severity="HIGH",
        summary_line="Auth-Bypass im Klick-Tracking behoben",
    )
    transport = FakeTransport()

    assert notify_critical_cve(sg, transport) is True
    assert notify_critical_cve(sg, transport) is False
    assert len(transport.zammad_tickets) == 1
    assert len(transport.slack_messages) == 1
    assert "CVE-2026-3104" in transport.zammad_tickets[0][0]
```

- [ ] **Step 2: Run pytest to verify the test fails**

Run: `cd backend && uv run pytest alerts/tests/test_router.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'alerts'`)

- [ ] **Step 3: Implement `alerts/models.py` and `alerts/router.py`**

Create `AlertFingerprint` model, HTTP transport for Slack webhooks and Zammad REST API (`POST /api/v1/tickets` with Bearer token), and `notify_critical_cve`, `notify_rollout_rollback`, and `build_weekly_digest`.

- [ ] **Step 4: Run pytest to verify the test passes**

Run: `cd backend && uv run pytest alerts/tests/test_router.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit Task 6**

```bash
git add backend/alerts/ backend/config/settings.py
git commit -m "feat(alerts): add deduplicated Slack, Zammad API, and weekly digest router"
```

---

### Task 7: Angular Frontend – `Nach Dienst` Master-Detail UI & Logos (`frontend/`)

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/angular.json`
- Create: `frontend/tsconfig.json`
- Create: `frontend/src/styles.scss`
- Create: `frontend/src/app/app.ts`
- Create: `frontend/src/app/app.routes.ts`
- Create: `frontend/src/app/core/logos.ts`
- Create: `frontend/src/app/core/patchbot-api.ts`
- Create: `frontend/src/app/pages/services-page.ts`
- Create: `frontend/src/app/pages/hosts-page.ts`
- Test: `frontend/src/app/pages/services-page.spec.ts`

**Interfaces:**
- Consumes: `GET /api/services/`, `POST /api/services/<slug>/plan/`, `POST /api/plans/<id>/execute/`, `GET /api/hosts/`
- Produces:
  - `logos.ts`: `SERVICE_LOGOS: Record<string, string>` (inline SVG markup for `plausible`, `django`, `postgres`, `coder`, `ubuntu`, `debian`, `traefik`, `valhalla`, `tileserver`) and `getLogoSvg(key: string, name: string): string`
  - `ServicesPage` (`services-page.ts`): 2-column Master-Detail workspace implementing `dashboard-overview-v2.html` (`Jetzt handeln` and `Bereit zum Ausrollen` sections on the left with 40×40px logos and zero row buttons; 45°-cut Plan panel on the right with the single `Bluefly 400` primary button `#execute-plan-btn`)

- [ ] **Step 1: Scaffold Angular 22 workspace in `frontend/` and write the failing component test in `frontend/src/app/pages/services-page.spec.ts`**

```typescript
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ServicesPage } from './services-page';

describe('ServicesPage', () => {
  it('renders service logos in two urgency groups and keeps a single primary action button in the plan panel', () => {
    TestBed.configureTestingModule({
      imports: [ServicesPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const httpMock = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(ServicesPage);
    fixture.detectChanges();

    httpMock.expectOne('/api/services/').flush([
      {
        slug: 'plausible',
        display_name: 'Plausible Analytics',
        logo_key: 'plausible',
        category: 'action_required',
        current_version_summary: '2.1.0',
        target_version: '2.1.2',
        highest_cve_id: 'CVE-2026-3104',
        summary_line: 'Auth-Bypass im Klick-Tracking behoben',
        git_targets: [{ repo_full_name: 'westcoder/westcode-web', file_path: 'deploy/compose.yaml', pr_number: 142, ci_status: 'success' }],
        host_targets: [
          { hostname: 'c2.westcode.de', working_dir: '/opt/plausible', running_version: '2.1.0', target_version: '2.1.2', git_clean: true },
        ],
      },
    ]);
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('.service-row').length).toBe(1);
    expect(el.querySelector('.service-row .svc-logo svg')).toBeTruthy();
    expect(el.querySelectorAll('.btn-primary').length).toBe(1);
    expect(el.querySelector('#execute-plan-btn')?.textContent).toContain('Plan ausführen');
  });
});
```

- [ ] **Step 2: Run `npm test` to verify the test fails**

Run: `cd frontend && npm test -- --watch=false`
Expected: FAIL (`Cannot find module './services-page'`)

- [ ] **Step 3: Implement `logos.ts`, `patchbot-api.ts`, `services-page.ts`, `hosts-page.ts`, and `styles.scss`**

Port the exact Westcode tokens (`--paper`, `--neutral-50`, `--bluefly-400`, `--salmon-700`, `--cut` 12px 45° polygon, `tabular-nums`) and Master-Detail structure from the approved `dashboard-overview-v2.html` mockup into `styles.scss` and `services-page.ts`.

- [ ] **Step 4: Run `npm test` to verify the component test passes**

Run: `cd frontend && npm test -- --watch=false`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit Task 7**

```bash
git add frontend/
git commit -m "feat(frontend): add Westcode CI service hierarchy view with logos and plan panel"
```

---

### Task 8: Hardened Deployment Stack, Renovate Config & Agent Installer (`deploy/`)

**Files:**
- Create: `deploy/compose.yaml`
- Create: `deploy/renovate.json`
- Create: `deploy/westcode-patchbot-agent.service`
- Create: `deploy/install-agent.sh`
- Test: `backend/fleet/tests/test_deploy_config.py`

**Interfaces:**
- Produces:
  - `deploy/compose.yaml`: hardened Docker Compose stack (`cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`) with `db` (`postgres:18-alpine`), `trivy` (`aquasec/trivy:latest server`), `backend`, and `renovate` runner
  - `deploy/westcode-patchbot-agent.service` & `deploy/install-agent.sh`: idempotent installer placing `patchbot_agent.py` in `/usr/local/libexec/westcode-patchbot-agent` and token in `/etc/westcode-patchbot/agent.env` (`0600`)

- [ ] **Step 1: Write the failing config validation test in `backend/fleet/tests/test_deploy_config.py`**

```python
import json
from pathlib import Path
import yaml


def test_deploy_compose_is_hardened_and_renovate_config_valid():
    root = Path(__file__).resolve().parents[3]
    compose = yaml.safe_load((root / "deploy" / "compose.yaml").read_text())

    assert "db" in compose["services"]
    assert "trivy" in compose["services"]
    assert "backend" in compose["services"]
    assert compose["services"]["backend"]["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in compose["services"]["backend"]["security_opt"]

    renovate = json.loads((root / "deploy" / "renovate.json").read_text())
    assert "poetry" in renovate["enabledManagers"]
    assert "docker-compose" in renovate["enabledManagers"]
```

- [ ] **Step 2: Run pytest to verify the test fails**

Run: `cd backend && uv run pytest fleet/tests/test_deploy_config.py -v`
Expected: FAIL (`FileNotFoundError: .../deploy/compose.yaml`)

- [ ] **Step 3: Create `deploy/compose.yaml`, `deploy/renovate.json`, `deploy/westcode-patchbot-agent.service`, and `deploy/install-agent.sh`**

Add `pyyaml>=6.0` to `backend/pyproject.toml` if needed, write the hardened compose file and Renovate config (`poetry`, `npm`, `dockerfile`, `docker-compose`), and write the systemd unit + installer script.

- [ ] **Step 4: Run the full backend and frontend test suites**

Run: `cd backend && PYTHONPATH=.. uv run pytest -v && cd ../frontend && npm test -- --watch=false`
Expected: PASS (all backend, agent, and frontend tests green)

- [ ] **Step 5: Commit Task 8**

```bash
git add deploy/ backend/
git commit -m "feat(deploy): add hardened compose stack, Renovate config, and systemd agent installer"
```
