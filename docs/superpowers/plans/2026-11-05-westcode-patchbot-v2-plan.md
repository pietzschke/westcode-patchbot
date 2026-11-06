# Westcode Patchbot v2 — Implementation Plan (for Spec v2.1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [`docs/superpowers/specs/2026-11-05-westcode-patchbot-v2-design.md`](../specs/2026-11-05-westcode-patchbot-v2-design.md) (v2.1, decisions D-1…D-5). Section references like **§6.4** point into that spec.

**Goal:** Turn the v1 prototype into the read-only Security & Update Triage Control Plane described in the spec: no host mutation, scan health with a grey Ampel state, deterministic policy gate around Claude, verified live rollouts, working-day deadlines, Slack-only notifications via signed public webhooks.

**Architecture:** Django 5.2 + DRF backend with the apps `fleet` (hosts, telemetry), `inventory` (team, projects, repositories, auth, GitHub client), `research` (scans, enrichment, Claude triage, PR engine, pipeline) and `triage` (findings, lifecycle, ownership, verification, notifications, webhooks, dashboard API, jobs); a stdlib push-only host agent; an Angular 22 frontend. Dependency direction: `research → triage → inventory → fleet` (`triage` never imports `research`).

**Tech stack:** Python 3.12, Django 5.2, DRF, PostgreSQL (SQLite in tests), `uv`, pytest + pytest-django, PyJWT[crypto], `anthropic`, `packaging`, `holidays`, Trivy CLI, Angular 22 with Vitest (`@angular/build:unit-test`).

---

## Conventions (apply to every task)

1. **TDD loop per task:**
   - [ ] Write the listed tests.
   - [ ] Run them; confirm they fail for the expected reason (missing module/field/endpoint, not a typo).
   - [ ] Implement until the task tests pass.
   - [ ] Run the full backend (and, for frontend tasks, frontend) suite.
   - [ ] Commit with the listed message.
2. **Commands:**
   - Backend task tests: `cd backend && uv run pytest <paths> -q`
   - Backend full suite: `cd backend && uv run pytest -q`
   - Frontend: `cd frontend && npx ng test --watch=false && npx ng build`
3. **New apps:** add to `INSTALLED_APPS` in `backend/config/settings.py` and the test directory to `testpaths` in `backend/pyproject.toml`.
4. **Test doubles** live in `backend/testing/` (created in Task 4): `factories.py` (model factories) and `fakes.py` (`FakeGitHub`, `FakeSlack`, `FakeLLM`). Every external system is injected; tests never hit the network.
5. **Time:** all lifecycle functions take `now: datetime | None` and default to `django.utils.timezone.now()`. Tests always pass `now` explicitly.
6. **Commits:** Conventional Commits, one commit per task, on a feature branch (never directly on `main`).

## Phase Overview

| Phase | Tasks | Outcome |
|---|---|---|
| 0 — Decommission & telemetry | 1–3 | No mutating paths left; agent v2 telemetry persisted |
| 1 — Inventory & auth | 4–8 | Team, projects, repos, sessions + Entra login, Notion sync, GitHub App, asset matching |
| 2 — Findings core | 9–12 | Working-day clock, version compare, `Finding` + dedupe, lifecycle, ownership |
| 3 — Research | 13–19 | Scan health, Trivy, KEV/EPSS, candidate collection, Claude + policy gate, PR engine, sandbox, maintenance list |
| 4 — Triage runtime | 20–25 | Live verification, dismissal, Slack notifications, webhooks, Ampel + REST API, worker & pipeline |
| 5 — Frontend | 26–30 | API client/auth, dashboard, detail panel, projects, hosts + team |
| 6 — Cleanup & rollout | 31–32 | v1 dashboard removed, deployment + agent rollout runbook |

---

## Phase 0 — Decommission & Telemetry

### Task 1: Remove v1 mutating paths

**Spec:** §2 Anti-Goals 1–2, §9 steps 1–3.

**Files:**
- Modify: `agent/patchbot_agent.py` (delete `ALLOWED_ACTION_TYPES`, `run_precheck`, `validate_opt_workdir`, `execute_compose_update`, `dispatch_agent_job`, apt-upgrade/reboot helpers; `main()` only posts the report)
- Modify: `agent/tests/test_agent.py` (delete tests of removed functions)
- Create: `agent/tests/test_agent_readonly.py`
- Modify: `backend/fleet/models.py` (delete `AgentJob`), `backend/fleet/api.py` (delete `AgentNextJobView`, `AgentJobResultView`), `backend/config/urls.py`
- Delete: `backend/rollouts/orchestrator.py`, `RolloutPlan`/`RolloutStep` in `backend/rollouts/models.py`, plan/execute views in `backend/rollouts/api.py`, `backend/rollouts/tests/test_orchestrator.py`
- Delete: `backend/alerts/` app (Zammad/email router); remove `"alerts"` from settings/testpaths; remove remaining `from alerts` imports (`grep -rn "from alerts" backend`)
- Modify: `backend/catalog/live_sync.py` (delete the block that creates `HostContainer` rows for hosts without agent)
- Delete: `frontend/src/app/pages/rollouts-page.ts` and its route/nav entry; remove plan/execute methods from `frontend/src/app/core/patchbot-api.ts`; adapt `services-page.spec.ts` (no „Plan ausführen“ button)
- Create: migrations `fleet/0002_delete_agentjob.py` (also deletes synthetic rows: `HostContainer.objects.filter(host__last_seen_at__isnull=True).delete()`), `rollouts/0002_delete_rollout_models.py`
- Create: `backend/fleet/tests/test_v1_decommission.py`

**Tests:**

```python
# agent/tests/test_agent_readonly.py
import agent.patchbot_agent as agent_mod


def test_agent_has_no_mutating_entrypoints():
    for name in (
        "ALLOWED_ACTION_TYPES",
        "dispatch_agent_job",
        "execute_compose_update",
        "run_precheck",
        "validate_opt_workdir",
    ):
        assert not hasattr(agent_mod, name), name


def test_main_only_posts_report_and_ignores_response(monkeypatch):
    calls = []

    def fake_http_json(url, method="GET", token="", payload=None):
        calls.append((method, url))
        # A compromised or legacy server answering with a job must be ignored.
        return {"id": "job-1", "action_type": "host_reboot", "payload": {}}

    monkeypatch.setattr(agent_mod, "_http_json", fake_http_json)
    monkeypatch.setattr(agent_mod, "collect_host_inventory", lambda runner=None: {"packages": [], "containers": []})

    rc = agent_mod.main(["--server-url", "https://patchbot.example", "--token", "t", "--hostname", "h1"])

    assert rc == 0
    assert calls == [("POST", "https://patchbot.example/api/agent/report/")]
```

```python
# backend/fleet/tests/test_v1_decommission.py
import importlib.util
import pytest
from django.urls import Resolver404, resolve


def _module_exists(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except ModuleNotFoundError:
        return False


@pytest.mark.parametrize(
    "path",
    [
        "/api/agent/jobs/next/",
        "/api/agent/jobs/00000000-0000-0000-0000-000000000000/result/",
        "/api/plans/",
        "/api/plans/00000000-0000-0000-0000-000000000000/execute/",
        "/api/services/plausible/plan/",
    ],
)
def test_v1_mutation_endpoints_are_gone(path):
    with pytest.raises(Resolver404):
        resolve(path)


def test_v1_mutation_modules_are_gone():
    assert not _module_exists("rollouts.orchestrator")
    assert not _module_exists("alerts.router")


@pytest.mark.django_db
def test_live_sync_never_fabricates_containers(tmp_path):
    from catalog.live_sync import WESTCODE_SERVICE_DEPLOYMENTS, run_live_sync
    from fleet.models import Host, HostContainer

    slug = WESTCODE_SERVICE_DEPLOYMENTS[0]["hosts"][0]
    Host.objects.create(slug=slug, hostname=f"{slug}.westcode.de", provider="hetzner", stack_name=f"hetzner-{slug}")

    run_live_sync(projects_root=tmp_path, run_trivy=False, run_gh=False)

    assert HostContainer.objects.count() == 0
```

**Implementation notes:** Keep the read-only views in `rollouts/api.py` (`ServiceListView`, `HostListView`, `HostDetailView`, `HostTokenGenerateView`, `ProjectListView`, `LiveSyncView`) until Task 31 so the v1 frontend keeps working in between.

**Commit:** `refactor!: remove agent job channel, rollout orchestrator, auto-merge and Zammad/email alerts`

---

### Task 2: Agent v2 telemetry & hardened oneshot unit

**Spec:** §4.2, §7.2.

**Files:**
- Modify: `agent/patchbot_agent.py`
- Modify: `agent/tests/test_agent.py` (`parse_apt_simulation` now also returns `source_pocket`)
- Create: `agent/tests/test_agent_telemetry_v2.py`
- Modify: `deploy/westcode-patchbot-agent.service`
- Modify: `backend/fleet/tests/test_deploy_config.py`

**Interfaces (produced):**
- `AGENT_VERSION = "2.0.0"`
- `collect_host_inventory(runner=None, os_release_path=..., reboot_required_path=..., apt_stamp_paths=(Path("/var/lib/apt/periodic/update-success-stamp"), Path("/var/lib/apt/lists"))) -> dict` with new keys `kernel_version`, `agent_version`, `apt_lists_updated_at` (ISO 8601 UTC or `""`), `packages[]` = **all installed packages** merged with upgrade candidates (`name`, `installed_version`, `candidate_version` (`""` if none), `is_security_update`, `source_pocket`), `containers[]` + `oci_source`, `image_created_at`, `git_head_sha`.

**Tests:**

```python
# agent/tests/test_agent_telemetry_v2.py
import json
from agent.patchbot_agent import AGENT_VERSION, collect_host_inventory

INSPECT = [{
    "Id": "c1", "Name": "/mdb-app", "Image": "sha256:img1", "State": {"Status": "running"},
    "Config": {
        "Image": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/materialdatenbank:main",
        "Labels": {
            "org.opencontainers.image.revision": "abc123",
            "org.opencontainers.image.source": "https://github.com/westcoder/materialdatenbank",
            "com.docker.compose.project.working_dir": "/opt/mdb",
            "com.docker.compose.service": "app",
        },
    },
}]
IMAGE = [{
    "RepoDigests": ["123456789012.dkr.ecr.eu-central-1.amazonaws.com/materialdatenbank@sha256:d1"],
    "Created": "2026-11-04T09:15:00.123456789Z",
}]
APT = "Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n"
DPKG = "openssl\t3.0.13-0ubuntu3.4\nlibc6\t2.39-0ubuntu8.3\n"

READ_ONLY_PREFIXES = [
    ["uname", "-r"],
    ["dpkg-query", "-W"],
    ["apt-get", "-s", "dist-upgrade"],
    ["docker", "ps"],
    ["docker", "inspect"],
    ["docker", "image", "inspect"],
]


class FakeRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, cwd=None):
        self.calls.append(list(argv))
        if argv[0] == "git":
            return (0, "" if "status" in argv else "f00dfeed\n", "")
        table = [
            (["uname", "-r"], "6.8.0-48-generic\n"),
            (["dpkg-query"], DPKG),
            (["apt-get"], APT),
            (["docker", "ps"], "c1\n"),
            (["docker", "inspect"], json.dumps(INSPECT)),
            (["docker", "image", "inspect"], json.dumps(IMAGE)),
        ]
        for prefix, out in table:
            if list(argv[: len(prefix)]) == prefix:
                return (0, out, "")
        return (1, "", "unexpected command")


def _collect(tmp_path, runner):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    stamp = tmp_path / "update-success-stamp"
    stamp.write_text("")
    return collect_host_inventory(
        runner=runner,
        os_release_path=os_release,
        reboot_required_path=tmp_path / "no-reboot",
        apt_stamp_paths=(stamp,),
    )


def test_collects_v2_host_fields(tmp_path):
    inv = _collect(tmp_path, FakeRunner())
    assert inv["kernel_version"] == "6.8.0-48-generic"
    assert inv["agent_version"] == AGENT_VERSION
    assert inv["apt_lists_updated_at"].endswith("+00:00")
    by_name = {p["name"]: p for p in inv["packages"]}
    assert by_name["openssl"] == {
        "name": "openssl",
        "installed_version": "3.0.13-0ubuntu3.4",
        "candidate_version": "3.0.13-0ubuntu3.5",
        "is_security_update": True,
        "source_pocket": "noble-security",
    }
    assert by_name["libc6"]["candidate_version"] == ""
    assert by_name["libc6"]["is_security_update"] is False


def test_collects_v2_container_fields(tmp_path):
    runner = FakeRunner()
    container = _collect(tmp_path, runner)["containers"][0]
    assert container["oci_source"] == "https://github.com/westcoder/materialdatenbank"
    assert container["oci_revision"] == "abc123"
    assert container["image_created_at"] == "2026-11-04T09:15:00.123456789Z"
    assert container["git_head_sha"] == "f00dfeed"
    assert container["git_clean"] is True
    assert ["git", "-c", "safe.directory=/opt/mdb", "rev-parse", "HEAD"] in runner.calls


def _is_read_only(argv):
    if argv[0] == "git":
        return (
            argv[1] == "-c"
            and argv[2].startswith("safe.directory=")
            and argv[3:] in (["rev-parse", "HEAD"], ["status", "--porcelain"])
        )
    return any(argv[: len(p)] == p for p in READ_ONLY_PREFIXES)


def test_every_subprocess_call_is_read_only(tmp_path):
    runner = FakeRunner()
    _collect(tmp_path, runner)
    assert runner.calls
    assert all(_is_read_only(c) for c in runner.calls), runner.calls
```

```python
# backend/fleet/tests/test_deploy_config.py (add)
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_agent_unit_is_hardened_oneshot():
    text = (REPO_ROOT / "deploy/westcode-patchbot-agent.service").read_text()
    for line in (
        "Type=oneshot",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "PrivateTmp=true",
        "NoNewPrivileges=true",
        "ReadOnlyPaths=/opt",
    ):
        assert line in text, line
    assert "Restart=" not in text
```

**Implementation notes:** `dpkg-query -W -f='${Package}\t${Version}\n'`. `source_pocket` = text after `/` in the origin field (`Ubuntu:24.04/noble-security` → `noble-security`); `is_security_update` stays `pocket.endswith("-security")`. Stamp mtime → `datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()`.

**Commit:** `feat(agent): report kernel, installed packages, apt freshness and OCI/git provenance; oneshot hardened unit`

---

### Task 3: Persist v2 telemetry in `fleet`

**Spec:** §4.2.

**Files:**
- Modify: `backend/fleet/models.py`, `backend/fleet/api.py`, `backend/fleet/infra_sync.py` (add `distro_eol_date(distro, version) -> date | None`)
- Create: `backend/fleet/migrations/0003_v2_telemetry.py`
- Create: `backend/fleet/tests/test_agent_report_v2.py`

**Model changes:** `Host`: `kernel_version`, `agent_version`, `apt_lists_updated_at` (nullable), `os_eol_date` (nullable). `HostContainer`: `oci_source`, `image_created_at` (nullable), `git_head_sha`, `reported_at`. `HostPackage`: `candidate_version` `blank=True, default=""`, `source_pocket`. The existing hostname/token mismatch check (`403`) stays.

**Tests:**

```python
# backend/fleet/tests/test_agent_report_v2.py
import hashlib
from datetime import datetime, timezone
import pytest
from rest_framework.test import APIClient
from fleet.infra_sync import DISTRO_EOL_DATES
from fleet.models import Host

TOKEN = "tok-mdb-secret"


@pytest.fixture
def host(db):
    return Host.objects.create(
        slug="mdb", hostname="mdb.westcode.de", provider="hetzner", stack_name="hetzner-mdb",
        agent_token_hash=hashlib.sha256(TOKEN.encode()).hexdigest(),
    )


def _post(payload):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {TOKEN}")
    return client.post("/api/agent/report/", data=payload, format="json")


REPORT = {
    "hostname": "mdb.westcode.de",
    "os_distro": "ubuntu",
    "os_version": "20.04",
    "kernel_version": "5.4.0-200-generic",
    "agent_version": "2.0.0",
    "apt_lists_updated_at": "2026-11-05T03:00:00+00:00",
    "reboot_required": False,
    "packages": [
        {"name": "openssl", "installed_version": "1.1.1f-1ubuntu2.22", "candidate_version": "1.1.1f-1ubuntu2.23",
         "is_security_update": True, "source_pocket": "focal-security"},
        {"name": "libc6", "installed_version": "2.31-0ubuntu9.16", "candidate_version": "",
         "is_security_update": False, "source_pocket": ""},
    ],
    "containers": [{
        "container_id": "c1", "name": "mdb-app", "image_tag": "ecr/materialdatenbank:main", "image_id": "sha256:img1",
        "repo_digests": ["ecr/materialdatenbank@sha256:d1"],
        "oci_revision": "abc123", "oci_source": "https://github.com/westcoder/materialdatenbank",
        "image_created_at": "2026-11-04T09:15:00.123456789Z",
        "working_dir": "/opt/mdb", "compose_service": "app", "git_head_sha": "f00dfeed", "git_clean": True,
        "status": "running",
    }],
}


def test_report_persists_v2_host_fields(host):
    assert _post(REPORT).status_code == 200
    host.refresh_from_db()
    assert host.kernel_version == "5.4.0-200-generic"
    assert host.agent_version == "2.0.0"
    assert host.apt_lists_updated_at == datetime(2026, 11, 5, 3, 0, tzinfo=timezone.utc)
    assert host.os_eol_date == DISTRO_EOL_DATES[("ubuntu", "20.04")]
    assert host.packages.count() == 2
    assert host.packages.get(name="openssl").source_pocket == "focal-security"
    assert host.packages.get(name="libc6").candidate_version == ""


def test_report_persists_v2_container_fields(host):
    _post(REPORT)
    c = host.containers.get()
    assert c.oci_source == "https://github.com/westcoder/materialdatenbank"
    assert c.image_created_at == datetime(2026, 11, 4, 9, 15, 0, 123456, tzinfo=timezone.utc)
    assert c.git_head_sha == "f00dfeed"
    assert c.reported_at is not None


def test_report_replaces_containers_in_full(host):
    _post(REPORT)
    _post({**REPORT, "containers": []})
    assert host.containers.count() == 0


def test_invalid_timestamps_are_stored_as_null(host):
    bad = {**REPORT, "apt_lists_updated_at": "yesterday",
           "containers": [{**REPORT["containers"][0], "image_created_at": "n/a"}]}
    assert _post(bad).status_code == 200
    host.refresh_from_db()
    assert host.apt_lists_updated_at is None
    assert host.containers.get().image_created_at is None
```

**Commit:** `feat(fleet): persist v2 host and container telemetry from agent reports`

---

## Phase 1 — Inventory & Auth

### Task 4: `inventory` models and shared test support

**Spec:** §4.1.

**Files:**
- Create: `backend/inventory/{__init__,apps,models,admin}.py`, `backend/inventory/migrations/0001_initial.py`
- Modify: `backend/fleet/models.py` — `Host.project`, `Host.suggested_project`, `HostContainer.project`, `HostContainer.repository` (string references `"inventory.Project"`, `"inventory.RepositoryAsset"`, `null=True, on_delete=SET_NULL`)
- Create: `backend/fleet/migrations/0004_project_links.py`
- Create: `backend/testing/__init__.py`, `backend/testing/factories.py`, `backend/testing/fakes.py` (extended by later tasks)
- Create: `backend/inventory/tests/__init__.py`, `backend/inventory/tests/test_models.py`

**Interfaces (produced):**
- `TeamMember` (fields per §4.1; `user` related_name `team_member`; `email` stored lowercase; `clean()` enforces a single active `is_default_infra_owner`)
- `Project` (fields per §4.1)
- `RepositoryAsset` (fields per §4.1; `deployment_mode` choices `CONTAINER|HOST_CHECKOUT|NONE|UNKNOWN`)
- `testing.factories`: `make_member(**kw)`, `make_project(**kw)`, `make_repo(**kw)`, `make_host(**kw)`, `make_container(host, **kw)`, `make_user_with_member(**kw) -> (User, TeamMember)`. Factories accept Django-style `relation__field` keyword arguments (e.g. `repository__deployment_mode="NONE"`) and generate unique defaults.

**Tests:**

```python
# backend/inventory/tests/test_models.py
import pytest
from django.core.exceptions import ValidationError
from testing.factories import make_member, make_project, make_repo


@pytest.mark.django_db
def test_email_is_normalised_to_lowercase():
    assert make_member(email="Moritz.Pietzschke@westcode.de").email == "moritz.pietzschke@westcode.de"


@pytest.mark.django_db
def test_only_one_active_default_infra_owner():
    make_member(email="infra1@westcode.de", is_default_infra_owner=True)
    second = make_member(email="infra2@westcode.de", is_default_infra_owner=False)
    second.is_default_infra_owner = True
    with pytest.raises(ValidationError):
        second.full_clean()


@pytest.mark.django_db
def test_inactive_default_infra_owner_does_not_block_new_one():
    make_member(email="old@westcode.de", is_default_infra_owner=True, is_active=False)
    new = make_member(email="new@westcode.de")
    new.is_default_infra_owner = True
    new.full_clean()


@pytest.mark.django_db
def test_repository_defaults():
    repo = make_repo(full_name="westcoder/materialdatenbank", project=make_project(slug="wuerth"))
    assert repo.deployment_mode == "UNKNOWN"
    assert repo.default_branch == "main"
    assert repo.project.repositories.get() == repo
```

**Commit:** `feat(inventory): add TeamMember, Project and RepositoryAsset models with shared test factories`

---

### Task 5: Authentication baseline (sessions, CSRF, permissions, health)

**Spec:** §7.1.

**Files:**
- Modify: `backend/config/settings.py` — add `django.contrib.sessions`, `SessionMiddleware`, `CsrfViewMiddleware`, `AuthenticationMiddleware`; `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE="Lax"`, `SESSION_COOKIE_AGE=43200`, `CSRF_COOKIE_SECURE`; `REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"], "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}`
- Modify: `backend/config/settings_test.py` — insecure cookies for the test client
- Create: `backend/config/checks.py` — `validate_dev_login(debug: bool, flag: str | None) -> None`, called at the end of `settings.py`
- Create: `backend/inventory/permissions.py` — `IsTeamMember`, `IsTeamAdmin`
- Create: `backend/inventory/views_auth.py` — `GET /api/auth/me/`, `POST /api/auth/logout/`, `POST /api/auth/dev-login/` (only registered when the dev bypass is active), `GET /api/health/`
- Modify: every existing view with `permission_classes = []` except `AgentReportView` (remove the override); `HostTokenGenerateView` → `IsTeamAdmin`
- Create: `backend/inventory/tests/test_auth_baseline.py`

**Tests:**

```python
# backend/inventory/tests/test_auth_baseline.py
import hashlib
import pytest
from django.core.exceptions import ImproperlyConfigured
from rest_framework.test import APIClient
from config.checks import validate_dev_login
from testing.factories import make_host, make_user_with_member


@pytest.mark.django_db
def test_api_requires_login_by_default():
    assert APIClient().get("/api/hosts/").status_code == 403


@pytest.mark.django_db
def test_health_is_public_and_leaks_nothing():
    resp = APIClient().get("/api/health/")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.django_db
def test_agent_report_still_uses_host_token():
    make_host(slug="mdb", hostname="mdb.westcode.de", agent_token_hash=hashlib.sha256(b"tok").hexdigest())
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Bearer tok")
    resp = client.post("/api/agent/report/", data={"hostname": "mdb.westcode.de", "packages": [], "containers": []}, format="json")
    assert resp.status_code == 200


@pytest.mark.django_db
def test_me_returns_bound_team_member():
    user, member = make_user_with_member(email="moritz.pietzschke@westcode.de", name="Moritz Pietzschke")
    client = APIClient()
    client.force_login(user)
    resp = client.get("/api/auth/me/")
    assert resp.status_code == 200
    assert resp.json()["email"] == "moritz.pietzschke@westcode.de"
    assert resp.json()["is_admin"] is False


@pytest.mark.django_db
def test_admin_only_endpoint_rejects_regular_member():
    make_host(slug="mdb", hostname="mdb.westcode.de")
    user, _ = make_user_with_member(email="dev@westcode.de", is_admin=False)
    admin, _ = make_user_with_member(email="admin@westcode.de", is_admin=True)
    client = APIClient()
    client.force_login(user)
    assert client.post("/api/hosts/mdb/token/").status_code == 403
    client.force_login(admin)
    assert client.post("/api/hosts/mdb/token/").status_code in (200, 201)


@pytest.mark.django_db
def test_unsafe_methods_require_csrf_token():
    make_host(slug="mdb", hostname="mdb.westcode.de")
    admin, _ = make_user_with_member(email="admin@westcode.de", is_admin=True)
    client = APIClient(enforce_csrf_checks=True)
    client.force_login(admin)
    assert client.post("/api/hosts/mdb/token/").status_code == 403


def test_dev_login_refused_without_debug():
    with pytest.raises(ImproperlyConfigured):
        validate_dev_login(debug=False, flag="1")
    validate_dev_login(debug=True, flag="1")
    validate_dev_login(debug=False, flag=None)
```

**Commit:** `feat(auth): enforce session authentication, CSRF and admin permissions across the API`

---

### Task 6: Microsoft Entra ID OIDC login

**Spec:** §7.1, §4.1 (`entra_object_id`).

**Files:**
- Modify: `backend/pyproject.toml` (`uv add "pyjwt[crypto]>=2.9"`)
- Create: `backend/inventory/entra.py`
- Modify: `backend/inventory/views_auth.py` — `GET /api/auth/entra/login/`, `GET /api/auth/entra/callback/`
- Create: `backend/inventory/tests/test_entra.py`

**Interfaces (produced):**
- `class EntraError(Exception)`
- `validate_tenant_id(tenant_id: str) -> None` (raises `ImproperlyConfigured` unless GUID)
- `build_authorization_url(session, *, tenant_id, client_id, redirect_uri) -> str` (stores `entra_state`, `entra_nonce`, `entra_code_verifier` in session; PKCE `S256`)
- `exchange_code(code, verifier, *, tenant_id, client_id, client_secret, redirect_uri, post=requests.post) -> dict`
- `fetch_jwks(tenant_id, get=requests.get) -> dict` (cached 1 h)
- `validate_id_token(id_token, *, jwks, tenant_id, client_id, nonce, leeway=60) -> dict`
- `bind_team_member(claims) -> TeamMember` (first login by email → stores `oid` and creates/links `User`; afterwards by `oid` only; refuses unknown, inactive, non-`@westcode.de`)

**Tests:**

```python
# backend/inventory/tests/test_entra.py
import json
import time
from urllib.parse import parse_qs, urlparse
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.exceptions import ImproperlyConfigured
from jwt.algorithms import RSAAlgorithm
from inventory.entra import EntraError, bind_team_member, validate_id_token, validate_tenant_id
from testing.factories import make_member

TENANT = "8f1c2a8e-0000-4000-8000-000000000001"
CLIENT = "11111111-2222-3333-4444-555555555555"


def _keypair(kid="k1"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = kid
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem, {"keys": [jwk]}


@pytest.fixture(scope="module")
def keypair():
    return _keypair()


def _token(pem, kid="k1", **overrides):
    now = int(time.time())
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": CLIENT, "tid": TENANT, "oid": "oid-1", "nonce": "n1",
        "email": "Moritz.Pietzschke@westcode.de", "name": "Moritz Pietzschke",
        "iat": now, "nbf": now, "exp": now + 600,
    }
    claims.update(overrides)
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})


def test_accepts_valid_token(keypair):
    pem, jwks = keypair
    claims = validate_id_token(_token(pem), jwks=jwks, tenant_id=TENANT, client_id=CLIENT, nonce="n1")
    assert claims["oid"] == "oid-1"


@pytest.mark.parametrize(
    "override",
    [
        {"aud": "other-client"},
        {"tid": "99999999-0000-4000-8000-000000000000"},
        {"iss": "https://login.microsoftonline.com/common/v2.0"},
        {"nonce": "replayed"},
        {"exp": int(time.time()) - 3600},
    ],
)
def test_rejects_invalid_claims(keypair, override):
    pem, jwks = keypair
    with pytest.raises(EntraError):
        validate_id_token(_token(pem, **override), jwks=jwks, tenant_id=TENANT, client_id=CLIENT, nonce="n1")


def test_rejects_token_signed_with_foreign_key(keypair):
    _, jwks = keypair
    foreign_pem, _ = _keypair()
    with pytest.raises(EntraError):
        validate_id_token(_token(foreign_pem), jwks=jwks, tenant_id=TENANT, client_id=CLIENT, nonce="n1")


@pytest.mark.parametrize("tenant", ["common", "organizations", "consumers", "westcode.de", ""])
def test_rejects_non_guid_tenant(tenant):
    with pytest.raises(ImproperlyConfigured):
        validate_tenant_id(tenant)


@pytest.mark.django_db
def test_binds_by_email_first_then_by_oid():
    member = make_member(email="moritz.pietzschke@westcode.de")
    bound = bind_team_member({"oid": "oid-1", "email": "Moritz.Pietzschke@westcode.de", "name": "Moritz"})
    member.refresh_from_db()
    assert bound == member
    assert member.entra_object_id == "oid-1"
    assert member.user is not None

    member.email = "renamed@westcode.de"
    member.save()
    assert bind_team_member({"oid": "oid-1", "email": "someone-else@westcode.de"}) == member


@pytest.mark.django_db
@pytest.mark.parametrize(
    "claims",
    [
        {"oid": "x1", "email": "ex@westcode.de"},
        {"oid": "x2", "email": "nobody@westcode.de"},
        {"oid": "x3", "email": "moritz@gmail.com"},
    ],
)
def test_refuses_inactive_unknown_or_foreign(claims):
    make_member(email="ex@westcode.de", is_active=False)
    with pytest.raises(EntraError):
        bind_team_member(claims)


@pytest.mark.django_db
def test_login_redirect_uses_pkce_and_stores_state(client, settings):
    settings.MICROSOFT_TENANT_ID = TENANT
    settings.MICROSOFT_CLIENT_ID = CLIENT
    resp = client.get("/api/auth/entra/login/")
    assert resp.status_code == 302
    url = urlparse(resp["Location"])
    query = parse_qs(url.query)
    assert url.netloc == "login.microsoftonline.com"
    assert url.path == f"/{TENANT}/oauth2/v2.0/authorize"
    assert query["code_challenge_method"] == ["S256"]
    assert query["client_id"] == [CLIENT]
    assert client.session["entra_state"] == query["state"][0]
    assert "entra_code_verifier" in client.session


@pytest.mark.django_db
def test_callback_rejects_state_mismatch(client, settings):
    settings.MICROSOFT_TENANT_ID = TENANT
    settings.MICROSOFT_CLIENT_ID = CLIENT
    client.get("/api/auth/entra/login/")
    assert client.get("/api/auth/entra/callback/?code=abc&state=forged").status_code == 400
```

**Implementation notes:** `jwt.decode(token, key=PyJWK(jwk).key, algorithms=["RS256"], audience=client_id, issuer=expected_iss, leeway=leeway, options={"require": ["exp", "nbf", "iat", "aud", "iss"]})`, then compare `tid` and `nonce` with `hmac.compare_digest`. Wrap every `jwt.PyJWTError` in `EntraError`. The callback calls `login(request, member.user)` (Django rotates the session key) and redirects to `/`.

**Commit:** `feat(auth): add single-tenant Entra ID OIDC login with PKCE, token validation and oid binding`

---

### Task 7: Notion project sync with precedence rules

**Spec:** §4.1 (`Project` precedence rules).

**Files:**
- Create: `backend/inventory/notion_sync.py`, `backend/inventory/signals.py` (`project_monitoring_changed = Signal()`; sent with `project`, `monitored`)
- Modify: `backend/config/settings.py` — `NOTION_API_KEY`, `NOTION_PROJECTS_DATABASE_ID`, `NOTION_ACTIVE_STATUSES = ["Aktiv", "Wartung"]`, `NOTION_ARCHIVED_STATUSES = ["Archiviert", "Abgeschlossen"]`, `NOTION_PROPERTY_NAMES = {"title": "Name", "status": "Status", "owner": "Projektleitung", "customer": "Kunde"}` (verify against the real Notion database before rollout)
- Create: `backend/inventory/tests/test_notion_sync.py`

**Interfaces (produced):**
- `sync_notion_projects(pages: list[dict] | None = None, *, fetch_pages=None, now=None) -> NotionSyncResult(created, updated, missing, unknown_statuses)`
- `fetch_all_pages(database_id, api_key, post=requests.post) -> list[dict]` (follows `has_more`/`next_cursor`, header `Notion-Version: 2022-06-28`)
- `set_monitoring(project, monitored: bool, *, source: str) -> None` (persists and sends the signal only on change)

**Tests:**

```python
# backend/inventory/tests/test_notion_sync.py
import pytest
from inventory.models import Project
from inventory.notion_sync import set_monitoring, sync_notion_projects
from inventory.signals import project_monitoring_changed
from testing.factories import make_member


def page(page_id, name, status, owner_email=None, customer="Würth", status_type="status"):
    return {
        "id": page_id,
        "properties": {
            "Name": {"type": "title", "title": [{"plain_text": name}]},
            "Status": {"type": status_type, status_type: {"name": status}},
            "Kunde": {"type": "rich_text", "rich_text": [{"plain_text": customer}]},
            "Projektleitung": {
                "type": "people",
                "people": [{"object": "user", "person": {"email": owner_email}}] if owner_email else [],
            },
        },
    }


@pytest.mark.django_db
def test_new_projects_are_monitored_only_when_active():
    owner = make_member(email="lead@westcode.de")
    result = sync_notion_projects([
        page("p1", "Würth", "Aktiv", owner_email="Lead@westcode.de"),
        page("p2", "Altkunde", "Archiviert"),
        page("p3", "Kugler", "Wartung", status_type="select"),
    ])
    assert result.created == 3
    assert Project.objects.get(notion_page_id="p1").is_monitored is True
    assert Project.objects.get(notion_page_id="p1").owner == owner
    assert Project.objects.get(notion_page_id="p1").slug == "wurth"
    assert Project.objects.get(notion_page_id="p2").is_monitored is False
    assert Project.objects.get(notion_page_id="p3").is_monitored is True


@pytest.mark.django_db
def test_unknown_status_is_treated_as_archived_and_reported():
    result = sync_notion_projects([page("p1", "Würth", "Pausiert")])
    assert Project.objects.get(notion_page_id="p1").is_monitored is False
    assert result.unknown_statuses == ["Pausiert"]


@pytest.mark.django_db
def test_manual_toggle_survives_sync_while_active():
    sync_notion_projects([page("p1", "Würth", "Aktiv")])
    set_monitoring(Project.objects.get(notion_page_id="p1"), False, source="WEB")
    sync_notion_projects([page("p1", "Würth", "Aktiv")])
    assert Project.objects.get(notion_page_id="p1").is_monitored is False


@pytest.mark.django_db
def test_archived_in_notion_forces_monitoring_off():
    sync_notion_projects([page("p1", "Würth", "Aktiv")])
    sync_notion_projects([page("p1", "Würth", "Abgeschlossen")])
    assert Project.objects.get(notion_page_id="p1").is_monitored is False


@pytest.mark.django_db
def test_reactivation_in_notion_does_not_turn_monitoring_on():
    sync_notion_projects([page("p1", "Würth", "Archiviert")])
    sync_notion_projects([page("p1", "Würth", "Aktiv")])
    assert Project.objects.get(notion_page_id="p1").is_monitored is False


@pytest.mark.django_db
def test_page_missing_from_notion_marks_project():
    sync_notion_projects([page("p1", "Würth", "Aktiv"), page("p2", "SES Sandmann", "Aktiv")])
    result = sync_notion_projects([page("p2", "SES Sandmann", "Aktiv")])
    p1 = Project.objects.get(notion_page_id="p1")
    assert result.missing == 1
    assert p1.notion_missing is True
    assert p1.is_monitored is False


@pytest.mark.django_db
def test_monitoring_signal_fires_only_on_change():
    received = []

    def handler(sender, project, monitored, **kwargs):
        received.append(monitored)

    project_monitoring_changed.connect(handler)
    try:
        sync_notion_projects([page("p1", "Würth", "Aktiv")])
        project = Project.objects.get(notion_page_id="p1")
        set_monitoring(project, True, source="WEB")
        set_monitoring(project, False, source="WEB")
    finally:
        project_monitoring_changed.disconnect(handler)
    assert received == [False]
```

**Commit:** `feat(inventory): sync Notion projects read-only with monitoring precedence rules`

---

### Task 8: GitHub App client, repository sync and asset matching

**Spec:** §3.2 (GitHub App), §4.1 (`RepositoryAsset`, auto-match signals).

**Files:**
- Create: `backend/inventory/github_app.py` — `GitHubApp` (installation token minting), `RestGitHubClient` (implements the protocol below)
- Create: `backend/inventory/matching.py`
- Extend: `backend/testing/fakes.py` — `FakeGitHub`
- Create: `backend/inventory/tests/test_github_app.py`, `backend/inventory/tests/test_matching.py`

**Interfaces (produced):** `GitHubClient` protocol, implemented by `RestGitHubClient` and `FakeGitHub`:

```python
@dataclass(frozen=True)
class CheckoutInfo:
    path: Path
    commit_sha: str


class GitHubClient(Protocol):
    def list_org_repos(self) -> list[dict]: ...            # {full_name, default_branch, archived}
    def file_exists(self, repo: str, path: str) -> bool: ...
    def checkout(self, repo: str) -> CheckoutInfo: ...     # fresh worktree of the default branch (Task 13 implements the mirror cache)
    def list_open_pulls(self, repo: str) -> list[dict]: ... # {number, html_url, user_login, head_ref, title, draft}
    def get_pull(self, repo: str, number: int) -> dict: ... # {state, merged, merged_at, merge_commit_sha, draft, html_url}
    def compare(self, repo: str, base: str, head: str) -> str: ...  # identical|ahead|behind|diverged
    def upsert_marker_comment(self, repo: str, number: int, marker: str, body: str) -> int: ...
    def create_pull(self, repo: str, *, head: str, base: str, title: str, body: str, draft: bool, labels: list[str]) -> dict: ...
    def push_branch(self, repo: str, branch: str, worktree: Path) -> None: ...  # refuses branches not starting with "patchbot/"
    def recent_file_authors(self, repo: str, paths: list[str], since: datetime) -> list[dict]: ...  # newest first {login, email, date}
    def combined_ci_status(self, repo: str, ref: str) -> str: ...
```

`FakeGitHub(repos=(), files=(), pulls=None, pull_details=None, compare=None, authors=(), head_shas=None)` records `comments: dict[(repo, number), list[str]]` (upsert by marker), `pushes: list[(repo, branch)]`, `created_pulls: list[dict]`, `author_queries: list[{"paths", "since"}]`; `checkout()` returns an empty temp dir and `head_shas.get(repo, "head")`; `compare()` returns `"identical"` when `base == head`.

- `matching.sync_repositories(github) -> dict` (creates/updates `RepositoryAsset`, `is_archived`, `has_bot_updates` if `renovate.json`, `.github/renovate.json` or `.github/dependabot.yml` exists)
- `matching.link_containers_to_repositories() -> int` (deterministic via `oci_source`; also copies `repository.project` to the container)
- `matching.suggest_projects() -> int` (fills `suggested_project` for unassigned repos/hosts/containers; never sets `project`)
- `matching.confirm_suggestion(asset) -> None`
- `matching.PROJECT_ALIASES = {"materialdatenbank": "wuerth", "wuerth-converter": "wuerth", "mdb": "wuerth", "converter": "wuerth"}` (curated; changes go through code review)

**Tests:**

```python
# backend/inventory/tests/test_github_app.py
import time
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from inventory.github_app import GitHubApp


class FakeSession:
    def __init__(self):
        self.calls = []

    def post(self, url, headers=None, timeout=None):
        self.calls.append((url, headers))

        class Response:
            status_code = 201

            def raise_for_status(self):
                pass

            def json(self):
                return {"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"}

        return Response()


def test_installation_token_is_minted_with_short_lived_app_jwt_and_cached():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    session = FakeSession()
    app = GitHubApp(app_id="12345", installation_id="678", private_key_pem=pem, session=session)

    assert app.installation_token() == "ghs_test"
    assert app.installation_token() == "ghs_test"
    assert len(session.calls) == 1

    url, headers = session.calls[0]
    assert url == "https://api.github.com/app/installations/678/access_tokens"
    claims = jwt.decode(headers["Authorization"].removeprefix("Bearer "), key.public_key(), algorithms=["RS256"])
    assert claims["iss"] == "12345"
    assert claims["exp"] - int(time.time()) <= 600
```

```python
# backend/inventory/tests/test_matching.py
import pytest
from inventory.matching import confirm_suggestion, link_containers_to_repositories, suggest_projects, sync_repositories
from inventory.models import RepositoryAsset
from testing.factories import make_container, make_host, make_project, make_repo
from testing.fakes import FakeGitHub


@pytest.mark.django_db
def test_sync_repositories_detects_archive_and_bot_config():
    gh = FakeGitHub(
        repos=[
            {"full_name": "westcoder/materialdatenbank", "default_branch": "main", "archived": False},
            {"full_name": "westcoder/old-site", "default_branch": "master", "archived": True},
        ],
        files={("westcoder/materialdatenbank", "renovate.json")},
    )
    sync_repositories(gh)
    mdb = RepositoryAsset.objects.get(full_name="westcoder/materialdatenbank")
    assert mdb.has_bot_updates is True
    assert RepositoryAsset.objects.get(full_name="westcoder/old-site").is_archived is True


@pytest.mark.django_db
def test_containers_link_to_repository_via_oci_source():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/materialdatenbank", project=wuerth)
    container = make_container(make_host(slug="mdb"), oci_source="https://github.com/westcoder/materialdatenbank")
    assert link_containers_to_repositories() == 1
    container.refresh_from_db()
    assert container.repository == repo
    assert container.project == wuerth


@pytest.mark.django_db
def test_suggestions_never_assign_directly():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/wuerth-converter")
    host = make_host(slug="converter", hostname="converter.westcode.de")
    suggest_projects()
    repo.refresh_from_db()
    host.refresh_from_db()
    assert repo.suggested_project == wuerth and repo.project is None
    assert host.suggested_project == wuerth and host.project is None


@pytest.mark.django_db
def test_confirm_suggestion_assigns_and_clears():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/wuerth-converter", suggested_project=wuerth)
    confirm_suggestion(repo)
    repo.refresh_from_db()
    assert repo.project == wuerth
    assert repo.suggested_project is None
```

**Implementation notes:** App JWT: `iat = now - 60`, `exp = now + 540`, `iss = app_id`, RS256. Cache the installation token until `expires_at - 5 min`. `push_branch` raises `ValueError` for any branch not starting with `patchbot/` (defence in depth next to the org ruleset).

**Commit:** `feat(inventory): add GitHub App client, repository sync and project auto-match suggestions`

---

## Phase 2 — Findings Core

### Task 9: Working-day clock (D-2)

**Spec:** §6.2 (working-day clock, KEV exception), §6.6 (posting window).

**Files:**
- Modify: `backend/pyproject.toml` (`uv add holidays`)
- Create: `backend/triage/{__init__,apps}.py`, `backend/triage/clock.py`
- Modify: `backend/config/settings.py` — `PATCHBOT_TIMEZONE = "Europe/Berlin"`, `PATCHBOT_HOLIDAY_SUBDIVISION = "NW"`, `PATCHBOT_EXTRA_HOLIDAYS = []` (ISO dates)
- Create: `backend/triage/tests/__init__.py`, `backend/triage/tests/test_clock.py`

**Interfaces (produced):**
- `default_holidays(years) -> set[date]` (`holidays.Germany(subdiv=settings.PATCHBOT_HOLIDAY_SUBDIVISION)` + extra dates)
- `add_working_days(start: datetime, days: int, holidays: set[date]) -> datetime`
- `deadline_for(*, stage: str, complexity: str, severity: str, kev_listed: bool, start: datetime, holidays: set[date]) -> datetime`
  - working days: `NEW` 1, `IN_PROGRESS` 2 (`SIMPLE`) / 5 (`COMPLEX`), `PR_MERGED_WAITING_LIVE` 1
  - `CRITICAL` + KEV, wall clock: `NEW` 24 h, `IN_PROGRESS` 48 h (`SIMPLE`) / 7 days (`COMPLEX`), `PR_MERGED_WAITING_LIVE` 24 h
- `next_posting_time(now: datetime, holidays: set[date]) -> datetime` (Mon–Fri working days, 08:00–18:00)

**Tests:**

```python
# backend/triage/tests/test_clock.py
from datetime import date, datetime
from zoneinfo import ZoneInfo
from triage.clock import add_working_days, deadline_for, next_posting_time

BER = ZoneInfo("Europe/Berlin")
HOL = {date(2026, 12, 25), date(2026, 12, 26)}


def dt(*args):
    return datetime(*args, tzinfo=BER)


def test_friday_plus_one_working_day_is_monday_same_time():
    assert add_working_days(dt(2026, 11, 6, 7, 0), 1, HOL) == dt(2026, 11, 9, 7, 0)


def test_weekend_start_counts_from_next_working_day_0800():
    assert add_working_days(dt(2026, 11, 7, 10, 0), 1, HOL) == dt(2026, 11, 10, 8, 0)


def test_holidays_are_skipped():
    assert add_working_days(dt(2026, 12, 24, 9, 0), 1, HOL) == dt(2026, 12, 28, 9, 0)


def test_five_working_days_from_thursday():
    assert add_working_days(dt(2026, 11, 5, 10, 0), 5, HOL) == dt(2026, 11, 12, 10, 0)


def test_complex_in_progress_uses_five_working_days():
    start = dt(2026, 11, 6, 7, 0)
    assert deadline_for(stage="IN_PROGRESS", complexity="COMPLEX", severity="HIGH", kev_listed=False,
                        start=start, holidays=HOL) == dt(2026, 11, 13, 7, 0)


def test_kev_critical_uses_wall_clock_hours():
    start = dt(2026, 11, 6, 7, 0)
    assert deadline_for(stage="NEW", complexity="SIMPLE", severity="CRITICAL", kev_listed=True,
                        start=start, holidays=HOL) == dt(2026, 11, 7, 7, 0)
    assert deadline_for(stage="IN_PROGRESS", complexity="SIMPLE", severity="CRITICAL", kev_listed=True,
                        start=start, holidays=HOL) == dt(2026, 11, 8, 7, 0)
    assert deadline_for(stage="IN_PROGRESS", complexity="COMPLEX", severity="CRITICAL", kev_listed=True,
                        start=start, holidays=HOL) == dt(2026, 11, 13, 7, 0)


def test_critical_without_kev_uses_working_days():
    assert deadline_for(stage="NEW", complexity="SIMPLE", severity="CRITICAL", kev_listed=False,
                        start=dt(2026, 11, 6, 7, 0), holidays=HOL) == dt(2026, 11, 9, 7, 0)


def test_posting_window():
    assert next_posting_time(dt(2026, 11, 7, 10, 0), HOL) == dt(2026, 11, 9, 8, 0)    # Saturday
    assert next_posting_time(dt(2026, 11, 9, 19, 0), HOL) == dt(2026, 11, 10, 8, 0)   # Monday evening
    assert next_posting_time(dt(2026, 11, 9, 6, 0), HOL) == dt(2026, 11, 9, 8, 0)     # Monday early
    assert next_posting_time(dt(2026, 11, 9, 9, 30), HOL) == dt(2026, 11, 9, 9, 30)   # inside window
    assert next_posting_time(dt(2026, 12, 25, 10, 0), HOL) == dt(2026, 12, 28, 8, 0)  # holiday
```

**Commit:** `feat(triage): add working-day deadline clock with KEV wall-clock exception`

---

### Task 10: Version comparison, `Finding` model and deduplicating upsert

**Spec:** §5.3, §6.1.

**Files:**
- Modify: `backend/pyproject.toml` (`uv add packaging`)
- Create: `backend/triage/versions.py` — `compare_versions(ecosystem, a, b) -> int` (`deb`/`ubuntu`/`debian` via the dpkg algorithm, `pypi`/`pip`/`uv`/`poetry` via `packaging.version`, `npm` and default via semver with prerelease handling)
- Create: `backend/triage/models.py` — `Finding`, `FindingEvent` (fields per §6.1; partial unique constraint on `(project, layer, target_ref, ecosystem, package_name)` for open states)
- Create: `backend/triage/candidates.py` — dataclasses `Vuln(id, severity, fixed_version)`, `Candidate(project, layer, target_ref, ecosystem, package_name, current_version, vulns, repository=None, host=None, image_ref="")`
- Create: `backend/triage/findings.py` — `upsert_finding(candidate, *, now=None) -> UpsertResult(finding, created, target_version_raised, muted)`; `log_event(finding, *, actor, source, from_state, to_state, note)`
- Extend: `backend/testing/factories.py` — `make_finding(**kw)` (creates project/repository on demand; supports `repository__…` keys)
- Create: `backend/triage/tests/test_versions.py`, `backend/triage/tests/test_upsert.py`

**Rules implemented by `upsert_finding`:**
- Open states: `NEW`, `IN_PROGRESS`, `PR_MERGED_WAITING_LIVE`. An open finding with the same key is updated (CVE ids merged, `target_version` = highest fixed version, severity/KEV recomputed; deadline untouched).
- Key matches a `DISMISSED` finding and all CVEs are already known → `muted=True`, nothing created.
- Key matches a `VERIFIED_LIVE` finding → new finding with `regression_of`.
- A new finding starts as `NEW`, `triage_status=UNTRIAGED`, `complexity=COMPLEX`, `deadline_at` from `deadline_for(stage="NEW", …)`; event `SYSTEM None→NEW`. Notifications are only sent after triage in the pipeline (Task 25), so a crash between upsert and triage leaves a visible, red, untriaged finding — never a silent one.

**Tests:**

```python
# backend/triage/tests/test_versions.py
import pytest
from triage.versions import compare_versions


@pytest.mark.parametrize(
    "eco,a,b,expected",
    [
        ("deb", "1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2.22", -1),
        ("deb", "3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.9", 1),
        ("deb", "1.0~rc1-1", "1.0-1", -1),
        ("deb", "1:1.0-1", "2.0-1", 1),
        ("pypi", "2.0.0rc1", "2.0.0", -1),
        ("pypi", "2.10.0", "2.9.1", 1),
        ("npm", "4.17.21", "4.17.9", 1),
        ("npm", "2.0.0-rc.1", "2.0.0", -1),
        ("npm", "1.2.3", "1.2.3", 0),
    ],
)
def test_compare_versions(eco, a, b, expected):
    assert compare_versions(eco, a, b) == expected
```

```python
# backend/triage/tests/test_upsert.py
from datetime import datetime
from zoneinfo import ZoneInfo
import pytest
from triage.candidates import Candidate, Vuln
from triage.findings import upsert_finding
from triage.models import Finding, FindingEvent
from testing.factories import make_project, make_repo

BER = ZoneInfo("Europe/Berlin")
NOW = datetime(2026, 11, 5, 7, 0, tzinfo=BER)  # Thursday


@pytest.fixture
def repo(db):
    return make_repo(full_name="westcoder/materialdatenbank", project=make_project(slug="wuerth"))


def cand(repo, *vulns):
    return Candidate(
        project=repo.project, layer="APPLICATION", target_ref=f"repo:{repo.full_name}", ecosystem="npm",
        package_name="lodash", current_version="4.17.15", vulns=list(vulns), repository=repo,
    )


def test_creates_new_untriaged_finding_with_deadline(repo):
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW)
    f = result.finding
    assert result.created
    assert f.state == "NEW"
    assert f.triage_status == "UNTRIAGED"
    assert f.complexity == "COMPLEX"
    assert f.deadline_at == datetime(2026, 11, 6, 7, 0, tzinfo=BER)
    assert FindingEvent.objects.filter(finding=f, to_state="NEW", source="SYSTEM").exists()


def test_same_key_updates_single_finding_and_takes_highest_fix(repo):
    upsert_finding(cand(repo, Vuln("CVE-2026-0001", "MEDIUM", "4.17.19")), now=NOW)
    upsert_finding(cand(repo, Vuln("CVE-2026-0002", "HIGH", "4.17.21")), now=NOW)
    f = Finding.objects.get()
    assert sorted(f.vulnerability_ids) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert f.target_version == "4.17.21"
    assert f.highest_severity == "HIGH"


def test_raising_target_in_progress_keeps_deadline(repo):
    f = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW).finding
    f.state = "IN_PROGRESS"
    f.save()
    deadline = f.deadline_at
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0002", "HIGH", "4.17.21")), now=NOW)
    f.refresh_from_db()
    assert result.target_version_raised is True
    assert f.deadline_at == deadline
    assert f.state == "IN_PROGRESS"


def test_dismissed_key_is_muted(repo):
    f = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW).finding
    f.state = "DISMISSED"
    f.save()
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW)
    assert result.muted is True
    assert Finding.objects.count() == 1


def test_redetection_after_verified_live_creates_regression(repo):
    f = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW).finding
    f.state = "VERIFIED_LIVE"
    f.save()
    result = upsert_finding(cand(repo, Vuln("CVE-2026-0001", "HIGH", "4.17.19")), now=NOW)
    assert result.created is True
    assert result.finding.regression_of == f
```

**Commit:** `feat(triage): add Finding model with deduplicating upsert and ecosystem-aware version comparison`

---

### Task 11: Lifecycle state machine and audit log

**Spec:** §6.2.

**Files:**
- Create: `backend/triage/lifecycle.py`
- Modify: `backend/triage/apps.py` — connect `project_monitoring_changed` to `on_monitoring_changed` in `ready()`
- Create: `backend/triage/tests/test_lifecycle.py`

**Interfaces (produced):**
- `class InvalidTransition(Exception)`
- `acknowledge(finding, actor: TeamMember, *, source: str, now=None) -> Finding` (reassigns to actor if different, logs both)
- `mark_pr_merged(finding, *, merge_commit_sha: str, merged_at: datetime, source: str, now=None) -> Finding` (from `NEW` or `IN_PROGRESS`; `deployment_mode == NONE` → `RESOLVED_NO_DEPLOYMENT`)
- `mark_fix_detected_on_branch(finding, *, commit_sha: str, now=None) -> Finding` (same as merge, note „Fix ohne Patchbot-PR erkannt“)
- `extend_deadline(finding, actor, *, reason: str, now=None) -> Finding` (once per stage, reason ≥ 15 chars, adds the stage's original length to the current deadline)
- `on_monitoring_changed(sender, project, monitored, **kwargs)` (open → `SUPPRESSED_UNMONITORED`; suppressed → `NEW` with fresh deadline)

**Tests:**

```python
# backend/triage/tests/test_lifecycle.py
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import pytest
from inventory.notion_sync import set_monitoring
from triage.lifecycle import InvalidTransition, acknowledge, extend_deadline, mark_pr_merged
from triage.models import FindingEvent
from testing.factories import make_finding, make_member

BER = ZoneInfo("Europe/Berlin")
NOW = datetime(2026, 11, 6, 7, 0, tzinfo=BER)  # Friday


@pytest.mark.django_db
def test_acknowledge_sets_in_progress_and_working_day_deadline():
    owner = make_member(email="owner@westcode.de")
    f = make_finding(state="NEW", complexity="SIMPLE", assignee=owner)
    acknowledge(f, owner, source="WEB", now=NOW)
    assert f.state == "IN_PROGRESS"
    assert f.acknowledged_at == NOW
    assert f.deadline_at == datetime(2026, 11, 10, 7, 0, tzinfo=BER)


@pytest.mark.django_db
def test_acknowledge_by_other_member_reassigns_and_logs():
    owner = make_member(email="owner@westcode.de")
    other = make_member(email="other@westcode.de")
    f = make_finding(state="NEW", assignee=owner)
    acknowledge(f, other, source="SLACK", now=NOW)
    assert f.assignee == other
    assert FindingEvent.objects.filter(finding=f, source="SLACK", note__icontains="übernommen").exists()


@pytest.mark.django_db
def test_merge_before_acknowledge_moves_to_waiting_live():
    f = make_finding(state="NEW")
    mark_pr_merged(f, merge_commit_sha="m1", merged_at=NOW, source="GITHUB", now=NOW)
    assert f.state == "PR_MERGED_WAITING_LIVE"
    assert f.deadline_at == datetime(2026, 11, 9, 7, 0, tzinfo=BER)


@pytest.mark.django_db
def test_merge_for_non_deployed_repo_resolves():
    f = make_finding(state="IN_PROGRESS", repository__deployment_mode="NONE")
    mark_pr_merged(f, merge_commit_sha="m1", merged_at=NOW, source="GITHUB", now=NOW)
    assert f.state == "RESOLVED_NO_DEPLOYMENT"


@pytest.mark.django_db
def test_extend_only_once_per_stage_with_reason():
    owner = make_member(email="owner@westcode.de")
    f = make_finding(state="IN_PROGRESS", complexity="SIMPLE", assignee=owner, deadline_at=NOW)
    with pytest.raises(ValueError):
        extend_deadline(f, owner, reason="zu kurz", now=NOW)
    extend_deadline(f, owner, reason="Warten auf Upstream-Release 2.4.1", now=NOW)
    assert f.deadline_at == NOW + timedelta(days=4)  # 2 working days from Friday 07:00 → Tuesday 07:00
    with pytest.raises(InvalidTransition):
        extend_deadline(f, owner, reason="Noch eine Verlängerung bitte", now=NOW)


@pytest.mark.django_db
def test_invalid_transition_raises():
    owner = make_member(email="owner@westcode.de")
    with pytest.raises(InvalidTransition):
        acknowledge(make_finding(state="VERIFIED_LIVE"), owner, source="WEB", now=NOW)


@pytest.mark.django_db
def test_monitoring_off_suppresses_and_on_reopens():
    f = make_finding(state="IN_PROGRESS")
    set_monitoring(f.project, False, source="WEB")
    f.refresh_from_db()
    assert f.state == "SUPPRESSED_UNMONITORED"
    set_monitoring(f.project, True, source="WEB")
    f.refresh_from_db()
    assert f.state == "NEW"
```

**Commit:** `feat(triage): add finding lifecycle transitions with audit events and monitoring suppression`

---

### Task 12: Ownership cascade

**Spec:** §6.3.

**Files:**
- Create: `backend/triage/ownership.py` — `resolve_assignee(finding, *, github, now=None) -> tuple[TeamMember | None, str]` and `assign(finding, *, github, now=None) -> Finding`
- Create: `backend/triage/tests/test_ownership.py`

**Tests:**

```python
# backend/triage/tests/test_ownership.py
from datetime import datetime, timezone
import pytest
from triage.ownership import resolve_assignee
from testing.factories import make_finding, make_member, make_project
from testing.fakes import FakeGitHub

NOW = datetime(2026, 11, 5, 7, 0, tzinfo=timezone.utc)


@pytest.fixture
def team(db):
    return {
        "infra": make_member(email="infra@westcode.de", is_default_infra_owner=True, slack_user_id="U1"),
        "owner": make_member(email="owner@westcode.de", slack_user_id="U2"),
        "dev": make_member(email="dev@westcode.de", github_username="dev-gh", slack_user_id="U3"),
        "alias": make_member(email="alias@westcode.de", git_commit_emails=["alias@users.noreply.github.com"], slack_user_id="U4"),
        "gone": make_member(email="gone@westcode.de", github_username="gone-gh", is_active=False, slack_user_id="U5"),
    }


def test_infrastructure_goes_to_default_infra_owner(team):
    f = make_finding(layer="INFRASTRUCTURE")
    assert resolve_assignee(f, github=FakeGitHub(), now=NOW)[0] == team["infra"]


def test_container_image_goes_to_project_owner(team):
    f = make_finding(layer="CONTAINER_IMAGE", project=make_project(owner=team["owner"]))
    assert resolve_assignee(f, github=FakeGitHub(), now=NOW)[0] == team["owner"]


def test_simple_application_ignores_lockfile_authors(team):
    gh = FakeGitHub(authors=[{"login": "dev-gh", "email": "dev@westcode.de", "date": NOW}])
    f = make_finding(layer="APPLICATION", complexity="SIMPLE", project=make_project(owner=team["owner"]))
    assert resolve_assignee(f, github=gh, now=NOW)[0] == team["owner"]
    assert gh.author_queries == []


def test_complex_application_picks_newest_active_human(team):
    gh = FakeGitHub(authors=[
        {"login": "renovate[bot]", "email": "bot@renovateapp.com", "date": NOW},
        {"login": "gone-gh", "email": "gone@westcode.de", "date": NOW},
        {"login": None, "email": "alias@users.noreply.github.com", "date": NOW},
        {"login": "dev-gh", "email": "dev@westcode.de", "date": NOW},
    ])
    f = make_finding(layer="APPLICATION", complexity="COMPLEX", affected_files=["src/api.ts:12"],
                     project=make_project(owner=team["owner"]))
    member, reason = resolve_assignee(f, github=gh, now=NOW)
    assert member == team["alias"]
    assert "Git" in reason
    assert gh.author_queries[0]["paths"] == ["src/api.ts"]
    assert gh.author_queries[0]["since"] == datetime(2025, 11, 5, 7, 0, tzinfo=timezone.utc)


def test_falls_back_to_project_owner(team):
    gh = FakeGitHub(authors=[{"login": "dependabot[bot]", "email": "x", "date": NOW}])
    f = make_finding(layer="APPLICATION", complexity="COMPLEX", affected_files=["a.py:1"],
                     project=make_project(owner=team["owner"]))
    assert resolve_assignee(f, github=gh, now=NOW)[0] == team["owner"]


def test_owner_without_slack_is_unassigned(team):
    no_slack = make_member(email="noslack@westcode.de", slack_user_id=None)
    f = make_finding(layer="CONTAINER_IMAGE", project=make_project(owner=no_slack))
    member, reason = resolve_assignee(f, github=FakeGitHub(), now=NOW)
    assert member is None
    assert "Slack" in reason
```

**Commit:** `feat(triage): add ownership cascade by layer and complexity`

---

## Phase 3 — Research

### Task 13: Scan runs, Trivy runner, repository mirror cache

**Spec:** §5.1, §5.2, §3.3 (repo cache).

**Files:**
- Create: `backend/research/{__init__,apps,models}.py` — `ScanRun`, `TargetScan`, `ImageScanCache(digest unique, scanned_at, status, report_json)`
- Create: `backend/research/trivy.py` — `run_trivy_fs(path, *, runner, timeout=300) -> TrivyResult`, `run_trivy_image(ref, *, runner, timeout=300) -> TrivyResult`, `update_trivy_db(runner)`; `TrivyScanner` (wraps both for the pipeline: `scan_repo(full_name, path)`, `scan_image(ref)`)
- Create: `backend/research/scan_runs.py` — `start_scan_run(trigger)`, `record_target(run, target_type, target_ref, result)`, `finalize_scan_run(run)`
- Create: `backend/research/repo_cache.py` — bare mirror per repo under `PATCHBOT_REPO_CACHE`, `git fetch` + fresh `git worktree add` of the default branch; used by `RestGitHubClient.checkout()`
- Create: `backend/research/tests/{__init__,test_trivy,test_scan_runs}.py`

**`TrivyResult`:** `status: "OK" | "FAILED"`, `error: str`, `vulnerabilities: list[dict]` with `id`, `package`, `installed`, `fixed`, `severity`, `ecosystem` (Trivy `Result.Type`), `pkg_class` (`os-pkgs` | `lang-pkgs`), `target`. Only `Status == "fixed"` and severity ≥ MEDIUM are kept.

**Tests:**

```python
# backend/research/tests/test_trivy.py
import json
import subprocess
from pathlib import Path
from research.trivy import run_trivy_fs, run_trivy_image

REPORT = {"Results": [
    {"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-0001", "PkgName": "lodash", "InstalledVersion": "4.17.15",
         "FixedVersion": "4.17.21", "Severity": "HIGH", "Status": "fixed"},
        {"VulnerabilityID": "CVE-2026-0002", "PkgName": "lodash", "InstalledVersion": "4.17.15",
         "FixedVersion": "4.17.21", "Severity": "LOW", "Status": "fixed"},
        {"VulnerabilityID": "CVE-2026-0003", "PkgName": "minimist", "InstalledVersion": "1.2.0",
         "Severity": "CRITICAL", "Status": "affected"},
    ]},
]}


def test_parses_and_keeps_only_fixed_medium_plus():
    result = run_trivy_fs(Path("/repo"), runner=lambda argv, timeout: (0, json.dumps(REPORT), ""))
    assert result.status == "OK"
    assert [v["id"] for v in result.vulnerabilities] == ["CVE-2026-0001"]
    assert result.vulnerabilities[0]["ecosystem"] == "npm"
    assert result.vulnerabilities[0]["pkg_class"] == "lang-pkgs"


def test_nonzero_exit_is_failed_not_clean():
    result = run_trivy_fs(Path("/repo"), runner=lambda argv, timeout: (2, "", "FATAL db error"))
    assert result.status == "FAILED"
    assert "db error" in result.error
    assert result.vulnerabilities == []


def test_timeout_is_failed():
    def runner(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    assert run_trivy_fs(Path("/repo"), runner=runner).status == "FAILED"


def test_invalid_json_is_failed():
    assert run_trivy_fs(Path("/repo"), runner=lambda argv, timeout: (0, "not json", "")).status == "FAILED"


def test_image_scan_uses_digest_reference_and_shared_db():
    seen = []

    def runner(argv, timeout):
        seen.append(argv)
        return (0, json.dumps({"Results": []}), "")

    run_trivy_image("123.dkr.ecr.eu-central-1.amazonaws.com/materialdatenbank@sha256:d1", runner=runner)
    assert seen[0][:2] == ["trivy", "image"]
    assert seen[0][-1].endswith("@sha256:d1")
    assert "--skip-db-update" in seen[0]
```

```python
# backend/research/tests/test_scan_runs.py
import pytest
from research.scan_runs import finalize_scan_run, record_target, start_scan_run
from research.trivy import TrivyResult


@pytest.mark.django_db
@pytest.mark.parametrize(
    "statuses,expected",
    [(["OK", "OK"], "OK"), (["OK", "FAILED"], "PARTIAL"), (["FAILED", "FAILED"], "FAILED"), ([], "OK")],
)
def test_finalize_derives_run_status(statuses, expected):
    run = start_scan_run("MANUAL")
    for i, status in enumerate(statuses):
        record_target(run, "REPO", f"repo:r{i}", TrivyResult(status=status, error="", vulnerabilities=[]))
    finalize_scan_run(run)
    assert run.status == expected
    assert run.finished_at is not None
```

**Commit:** `feat(research): add scan run health tracking and a Trivy runner that never treats failures as clean`

---

### Task 14: Exploit signals (CISA KEV, EPSS)

**Spec:** §3.1, §5.3.

**Files:**
- Modify: `backend/research/models.py` — `ExploitSignal(cve_id pk, kev_listed, kev_added_at, epss, updated_at)`
- Create: `backend/research/signals_feed.py` — `refresh_kev(fetch=...) -> int`, `refresh_epss(cve_ids, fetch=..., batch_size=100) -> int`, `apply_signals(finding) -> bool` (sets `kev_listed`, `max_epss`; returns `True` if either changed)
- Create: `backend/research/tests/test_signals_feed.py`

**Tests:**

```python
# backend/research/tests/test_signals_feed.py
import pytest
from research.models import ExploitSignal
from research.signals_feed import refresh_epss, refresh_kev


@pytest.mark.django_db
def test_refresh_kev_marks_listed_cves():
    feed = {"vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-10-01"}]}
    assert refresh_kev(fetch=lambda: feed) == 1
    assert ExploitSignal.objects.get(cve_id="CVE-2026-0001").kev_listed is True


@pytest.mark.django_db
def test_refresh_kev_failure_keeps_previous_state():
    ExploitSignal.objects.create(cve_id="CVE-2026-0001", kev_listed=True)

    def broken():
        raise ConnectionError("feed down")

    with pytest.raises(ConnectionError):
        refresh_kev(fetch=broken)
    assert ExploitSignal.objects.get(cve_id="CVE-2026-0001").kev_listed is True


@pytest.mark.django_db
def test_refresh_epss_batches_requests():
    calls = []

    def fetch(batch):
        calls.append(batch)
        return {"data": [{"cve": c, "epss": "0.12"} for c in batch]}

    ids = [f"CVE-2026-{i:04d}" for i in range(250)]
    assert refresh_epss(ids, fetch=fetch) == 250
    assert [len(c) for c in calls] == [100, 100, 50]
    assert ExploitSignal.objects.get(cve_id="CVE-2026-0000").epss == pytest.approx(0.12)
```

**Commit:** `feat(research): ingest CISA KEV and EPSS exploit signals`

---

### Task 15: Candidate collection across repository, image and host layers

**Spec:** §5.2, §5.3 (fix detected before merge).

**Files:**
- Create: `backend/research/collect.py` — `collect_and_upsert(run, *, github, trivy, now=None) -> CollectResult(created, updated, muted, findings)`
- Create: `backend/research/tests/test_collect.py`

**Rules:**
- Only `Project.is_monitored=True` and not `RepositoryAsset.is_archived`.
- Repo targets: `github.checkout(repo)` → `trivy.scan_repo(full_name, path)`; target ref `repo:<full_name>`.
- Image targets: distinct digests of running containers linked to monitored projects; `ImageScanCache` reused for 24 h; target ref `image:<registry/repository>` (no tag/digest); `os-pkgs` only, plus `lang-pkgs` when the container has no linked repository.
- Host targets: security-pocket packages (one candidate per package, ecosystem `deb`), `reboot_required` (package `__reboot__`), OS EOL past or within 90 days (package `__os_eol__`).
- **Failed target** → `record_target(..., FAILED)`; findings of that target are not touched.
- **OK repo target where a previously open CVE is gone** → `mark_fix_detected_on_branch(finding, commit_sha=checkout.commit_sha)`.

**Tests:**

```python
# backend/research/tests/test_collect.py
from datetime import date, datetime, timezone
import pytest
from research.collect import collect_and_upsert
from research.models import TargetScan
from research.scan_runs import start_scan_run
from research.trivy import TrivyResult
from triage.models import Finding
from testing.factories import make_container, make_finding, make_host, make_project, make_repo
from testing.fakes import FakeGitHub

NOW = datetime(2026, 11, 5, 6, 0, tzinfo=timezone.utc)
LODASH = {"id": "CVE-2026-0001", "package": "lodash", "installed": "4.17.15", "fixed": "4.17.21",
          "severity": "HIGH", "ecosystem": "npm", "pkg_class": "lang-pkgs", "target": "package-lock.json"}


class FakeTrivy:
    def __init__(self, fs=None, image=None):
        self.fs = fs or {}
        self.image = image or {}
        self.fs_calls, self.image_calls = [], []

    def scan_repo(self, full_name, path):
        self.fs_calls.append(full_name)
        return self.fs.get(full_name, TrivyResult("OK", "", []))

    def scan_image(self, ref):
        self.image_calls.append(ref)
        return self.image.get(ref, TrivyResult("OK", "", []))


@pytest.mark.django_db
def test_only_monitored_projects_are_scanned():
    make_repo(full_name="westcoder/active", project=make_project(slug="a", is_monitored=True))
    make_repo(full_name="westcoder/archived", project=make_project(slug="b", is_monitored=False))
    trivy = FakeTrivy()
    collect_and_upsert(start_scan_run("MANUAL"), github=FakeGitHub(), trivy=trivy, now=NOW)
    assert trivy.fs_calls == ["westcoder/active"]


@pytest.mark.django_db
def test_failed_target_keeps_existing_findings():
    repo = make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"))
    existing = make_finding(repository=repo, project=repo.project, state="NEW", package_name="lodash")
    trivy = FakeTrivy(fs={"westcoder/mdb": TrivyResult("FAILED", "db error", [])})
    run = start_scan_run("MANUAL")
    collect_and_upsert(run, github=FakeGitHub(), trivy=trivy, now=NOW)
    existing.refresh_from_db()
    assert existing.state == "NEW"
    assert TargetScan.objects.get(scan_run=run).status == "FAILED"


@pytest.mark.django_db
def test_fix_on_default_branch_moves_finding_to_live_verification():
    repo = make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth"), deployment_mode="CONTAINER")
    existing = make_finding(repository=repo, project=repo.project, state="IN_PROGRESS", package_name="lodash")
    gh = FakeGitHub(head_shas={"westcoder/mdb": "c0ffee"})
    collect_and_upsert(start_scan_run("MANUAL"), github=gh, trivy=FakeTrivy(), now=NOW)
    existing.refresh_from_db()
    assert existing.state == "PR_MERGED_WAITING_LIVE"
    assert existing.merge_commit_sha == "c0ffee"


@pytest.mark.django_db
def test_same_digest_is_scanned_once_and_lang_pkgs_go_to_application_layer():
    wuerth = make_project(slug="wuerth")
    repo = make_repo(full_name="westcoder/mdb", project=wuerth)
    for slug in ("mdb", "mdb2"):
        make_container(make_host(slug=slug, project=wuerth), project=wuerth, repository=repo,
                       repo_digests=["ecr/materialdatenbank@sha256:d1"])
    image_result = TrivyResult("OK", "", [
        {**LODASH},
        {"id": "CVE-2026-0100", "package": "openssl", "installed": "3.0.13-0ubuntu3.4", "fixed": "3.0.13-0ubuntu3.5",
         "severity": "HIGH", "ecosystem": "ubuntu", "pkg_class": "os-pkgs", "target": "ubuntu 24.04"},
    ])
    trivy = FakeTrivy(fs={"westcoder/mdb": TrivyResult("OK", "", [LODASH])},
                      image={"ecr/materialdatenbank@sha256:d1": image_result})
    collect_and_upsert(start_scan_run("MANUAL"), github=FakeGitHub(), trivy=trivy, now=NOW)
    assert trivy.image_calls == ["ecr/materialdatenbank@sha256:d1"]
    layers = sorted(Finding.objects.values_list("layer", "package_name"))
    assert layers == [("APPLICATION", "lodash"), ("CONTAINER_IMAGE", "openssl")]


@pytest.mark.django_db
def test_host_layer_candidates():
    host = make_host(slug="mdb", project=make_project(slug="wuerth"), reboot_required=True,
                     os_distro="ubuntu", os_version="20.04", os_eol_date=date(2025, 5, 31))
    host.packages.create(name="openssl", installed_version="1.1.1f-1ubuntu2.22",
                         candidate_version="1.1.1f-1ubuntu2.23", is_security_update=True, source_pocket="focal-security")
    collect_and_upsert(start_scan_run("MANUAL"), github=FakeGitHub(), trivy=FakeTrivy(), now=NOW)
    assert sorted(Finding.objects.filter(layer="INFRASTRUCTURE").values_list("package_name", flat=True)) == [
        "__os_eol__", "__reboot__", "openssl",
    ]
```

**Commit:** `feat(research): collect repository, image and host candidates for monitored projects`

---

### Task 16: Claude triage and deterministic policy gate

**Spec:** §5.4.

**Files:**
- Modify: `backend/pyproject.toml` (`uv add anthropic`)
- Modify: `backend/config/settings.py` — `PATCHBOT_CLAUDE_MODEL = os.environ.get("PATCHBOT_CLAUDE_MODEL", "claude-sonnet-5-5")`, `PATCHBOT_TRIAGE_PROMPT_VERSION = "2026-11-05.1"`
- Modify: `backend/research/models.py` — `TriageAnalysisCache(cache_key unique, result_json, created_at)`
- Create: `backend/research/evidence.py` — `is_dev_only(checkout, ecosystem, package) -> bool` (npm `package-lock.json` `"dev": true`; `uv.lock`/`poetry.lock` dev groups), `call_site_hits(checkout, ecosystem, package) -> int` (excludes `node_modules`, `.git`, `vendor`, `dist`)
- Create: `backend/research/triage_ai.py` — `TRIAGE_TOOL` (JSON schema of §5.4), `TriageResult`, `analyze(finding, context, *, client) -> TriageResult | None`, `policy_gate(finding, result, evidence) -> bool`, `apply_triage(finding, *, client, checkout, now=None) -> Finding`
- Extend: `backend/testing/fakes.py` — `FakeLLM(tool_input)` (records kwargs in `calls`; returns a message whose `content` holds one `tool_use` block named `record_triage`)
- Create: `backend/research/tests/test_policy_gate.py`, `backend/research/tests/test_triage_ai.py`, `backend/research/tests/test_evidence.py`

**Implementation notes (as built):** forced `tool_choice` returns a 400 on `claude-sonnet-5-5`, so the request uses structured outputs: `client.beta.messages.create(model=..., max_tokens=16000, system=[{..., "cache_control": {"type": "ephemeral"}}], output_config={"format": {"type": "json_schema", "schema": TRIAGE_SCHEMA}}, betas=["server-side-fallback-2026-07-01"], fallbacks="default")`. External text goes into `<untrusted_…>` blocks. Patchbot re-validates the JSON (enums, `0 ≤ confidence ≤ 1`). API errors, `stop_reason` `refusal`/`max_tokens` or invalid output → `UNTRIAGED`/`COMPLEX` with an event note. Cache key: `sha256(cluster key | target version | CVE ids | commit | prompt version | model)`. Tests use `FakeLLM(output=...)`.

**Tests:**

```python
# backend/research/tests/test_policy_gate.py
from types import SimpleNamespace
import pytest
from research.triage_ai import TriageResult, policy_gate


def finding(severity="HIGH", kev=False, epss=0.01):
    return SimpleNamespace(highest_severity=severity, kev_listed=kev, max_epss=epss)


def result(reach="NOT_REACHABLE", conf=0.9, cat="DEV_ONLY"):
    return TriageResult(reachability=reach, reachability_reason_category=cat, complexity="SIMPLE",
                        confidence=conf, summary_de="", breaking_changes_de="", affected_files=[])


@pytest.mark.parametrize(
    "f,r,evidence,expected",
    [
        (finding(), result(), {"dev_only": True, "call_site_hits": 3}, True),
        (finding(severity="CRITICAL"), result(), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(kev=True), result(), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(epss=0.2), result(), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(), result(conf=0.7), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(), result(reach="UNLIKELY_REACHABLE"), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(), result(), {"dev_only": False, "call_site_hits": 0}, False),
        (finding(severity="MEDIUM"), result(cat="NO_CALL_SITE"), {"dev_only": False, "call_site_hits": 0}, True),
        (finding(severity="MEDIUM"), result(cat="NO_CALL_SITE"), {"dev_only": False, "call_site_hits": 2}, False),
        (finding(severity="MEDIUM"), result(cat="UNUSED_FEATURE"), {"dev_only": False, "call_site_hits": 0}, False),
    ],
)
def test_policy_gate(f, r, evidence, expected):
    assert policy_gate(f, r, evidence) is expected
```

```python
# backend/research/tests/test_triage_ai.py
import pytest
from research.triage_ai import apply_triage
from testing.factories import make_finding
from testing.fakes import FakeLLM

VALID = {
    "reachability": "REACHABLE", "reachability_reason_category": "OTHER", "complexity": "SIMPLE",
    "confidence": 0.85, "summary_de": "lodash.template wird in src/report.ts genutzt.",
    "breaking_changes_de": "", "affected_files": ["src/report.ts:42"],
}


@pytest.mark.django_db
def test_uses_forced_tool_configured_model_and_untrusted_blocks(settings, tmp_path):
    settings.PATCHBOT_CLAUDE_MODEL = "claude-sonnet-5-5"
    llm = FakeLLM(tool_input=VALID)
    f = make_finding(layer="APPLICATION", package_name="lodash")
    apply_triage(f, client=llm, checkout=tmp_path)
    call = llm.calls[0]
    assert call["model"] == "claude-sonnet-5-5"
    assert call["tool_choice"] == {"type": "tool", "name": "record_triage"}
    assert "<untrusted_advisory>" in call["messages"][0]["content"]
    assert f.triage_status == "TRIAGED"
    assert f.complexity == "SIMPLE"
    assert f.state == "NEW"


@pytest.mark.django_db
def test_no_client_means_untriaged_and_relevant(tmp_path):
    f = make_finding(layer="APPLICATION")
    apply_triage(f, client=None, checkout=tmp_path)
    assert (f.triage_status, f.complexity, f.state) == ("UNTRIAGED", "COMPLEX", "NEW")


@pytest.mark.django_db
def test_invalid_model_output_means_untriaged(tmp_path):
    f = make_finding(layer="APPLICATION")
    apply_triage(f, client=FakeLLM(tool_input={**VALID, "reachability": "MAYBE"}), checkout=tmp_path)
    assert f.triage_status == "UNTRIAGED"


@pytest.mark.django_db
def test_analysis_is_cached(tmp_path):
    llm = FakeLLM(tool_input=VALID)
    f = make_finding(layer="APPLICATION", package_name="lodash", target_version="4.17.21")
    apply_triage(f, client=llm, checkout=tmp_path)
    apply_triage(f, client=llm, checkout=tmp_path)
    assert len(llm.calls) == 1


@pytest.mark.django_db
def test_filtered_only_through_policy_gate(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/jest": {"version": "29.0.0", "dev": true}}}'
    )
    llm = FakeLLM(tool_input={**VALID, "reachability": "NOT_REACHABLE",
                              "reachability_reason_category": "DEV_ONLY", "confidence": 0.95})
    f = make_finding(layer="APPLICATION", ecosystem="npm", package_name="jest", highest_severity="HIGH")
    apply_triage(f, client=llm, checkout=tmp_path)
    assert f.state == "FILTERED_IRRELEVANT"


@pytest.mark.django_db
@pytest.mark.parametrize("package,expected", [("openssl", "SIMPLE"), ("__reboot__", "SIMPLE"), ("__os_eol__", "COMPLEX")])
def test_infrastructure_skips_llm(package, expected):
    llm = FakeLLM(tool_input=VALID)
    f = make_finding(layer="INFRASTRUCTURE", package_name=package)
    apply_triage(f, client=llm, checkout=None)
    assert f.complexity == expected
    assert llm.calls == []
```

```python
# backend/research/tests/test_evidence.py
from research.evidence import call_site_hits, is_dev_only


def test_npm_dev_flag(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/jest": {"version": "29.0.0", "dev": true},'
        ' "node_modules/lodash": {"version": "4.17.15"}}}'
    )
    assert is_dev_only(tmp_path, "npm", "jest") is True
    assert is_dev_only(tmp_path, "npm", "lodash") is False


def test_call_site_hits_ignore_vendor_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.ts").write_text("import _ from 'lodash';\n")
    (tmp_path / "node_modules/x").mkdir(parents=True)
    (tmp_path / "node_modules/x/index.js").write_text("require('lodash')\n")
    assert call_site_hits(tmp_path, "npm", "lodash") == 1
```

**Commit:** `feat(research): add Claude triage with structured output, caching and a deterministic policy gate`

---

### Task 17: PR engine — bot PR reuse and deterministic Fix-PRs

**Spec:** §5.5 (principles, cases 1–2).

**Files:**
- Create: `backend/research/bot_prs.py` — `parse_bot_pr(pr) -> BotPr | None` (regex moved from `catalog/renovate_sync.py`; only `renovate[bot]` / `dependabot[bot]`)
- Create: `backend/research/bumper.py` — `Bumper.bump(worktree, ecosystem, package, version) -> list[str]`; npm: `npm install <pkg>@<ver> --package-lock-only --ignore-scripts`; Python/uv: `uv lock --upgrade-package <pkg>==<ver>`; other ecosystems raise `BumpFailed("unsupported ecosystem")`
- Create: `backend/research/pr_engine.py` — `TRIAGE_MARKER = "<!-- patchbot:triage -->"`, `ensure_pr(finding, *, github, bumper, worktrees, sandbox=None, llm=None, now=None) -> PrOutcome`
- Create: `backend/research/tests/test_pr_engine.py`

**Tests:**

```python
# backend/research/tests/test_pr_engine.py
import pytest
from research.bumper import BumpFailed
from research.pr_engine import TRIAGE_MARKER, ensure_pr
from testing.factories import make_finding
from testing.fakes import FakeGitHub

REPO = "westcoder/materialdatenbank"


class FakeBumper:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def bump(self, worktree, ecosystem, package, version):
        self.calls.append((ecosystem, package, version))
        if self.fail:
            raise BumpFailed("ERESOLVE could not resolve")
        return ["package.json", "package-lock.json"]


class FakeWorktrees:
    def create(self, repo, base, branch):
        return f"/tmp/wt/{branch}"


def finding(**kw):
    defaults = dict(layer="APPLICATION", complexity="SIMPLE", ecosystem="npm", package_name="lodash",
                    target_version="4.17.21", repository__full_name=REPO, summary_de="Analyse")
    defaults.update(kw)
    return make_finding(**defaults)


@pytest.mark.django_db
def test_reuses_bot_pr_and_upserts_single_comment():
    gh = FakeGitHub(pulls={REPO: [{"number": 41, "html_url": "u41", "user_login": "renovate[bot]",
                                   "head_ref": "renovate/lodash-4.x", "title": "Update dependency lodash to v4.17.21",
                                   "draft": False}]})
    f = finding()
    ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees())
    ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees())
    assert (f.pr_number, f.pr_source) == (41, "BOT")
    comments = gh.comments[(REPO, 41)]
    assert len(comments) == 1 and TRIAGE_MARKER in comments[0]
    assert gh.pushes == []
    assert gh.created_pulls == []


@pytest.mark.django_db
def test_bot_pr_with_insufficient_version_is_not_reused():
    gh = FakeGitHub(pulls={REPO: [{"number": 40, "html_url": "u40", "user_login": "renovate[bot]",
                                   "head_ref": "renovate/lodash", "title": "Update dependency lodash to v4.17.19",
                                   "draft": False}]})
    f = finding()
    ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees())
    assert f.pr_number != 40


@pytest.mark.django_db
def test_simple_without_bot_pr_creates_ready_pr_on_patchbot_branch():
    gh = FakeGitHub()
    bumper = FakeBumper()
    f = finding()
    ensure_pr(f, github=gh, bumper=bumper, worktrees=FakeWorktrees())
    pr = gh.created_pulls[0]
    assert pr["head"] == "patchbot/lodash-4.17.21"
    assert pr["base"] == "main"
    assert pr["draft"] is False
    assert "patchbot:ai-generated" not in pr["labels"]
    assert f.pr_source == "PATCHBOT"
    assert bumper.calls == [("npm", "lodash", "4.17.21")]
    assert all(branch.startswith("patchbot/") for _, branch in gh.pushes)


@pytest.mark.django_db
def test_bump_failure_reclassifies_complex_without_pr():
    gh = FakeGitHub()
    f = finding()
    ensure_pr(f, github=gh, bumper=FakeBumper(fail=True), worktrees=FakeWorktrees())
    assert f.complexity == "COMPLEX"
    assert f.pr_number is None
    assert gh.created_pulls == []


@pytest.mark.django_db
def test_existing_open_patchbot_pr_is_not_duplicated():
    gh = FakeGitHub(pull_details={(REPO, 77): {"state": "open", "merged": False}})
    f = finding(pr_number=77, pr_source="PATCHBOT")
    ensure_pr(f, github=gh, bumper=FakeBumper(), worktrees=FakeWorktrees())
    assert gh.created_pulls == []
```

**Commit:** `feat(research): reuse Renovate/Dependabot PRs with triage comments and open deterministic Fix-PRs`

---

### Task 18: Code-patching sandbox and diff gate (Draft-PRs)

**Spec:** §5.5 (case 3, sandbox, diff gate), §7.4.

**As built:** `ensure_pr(..., patcher=None)` takes a `patcher(finding, worktree) -> PatchLoopResult` (production: `SandboxPatcher`), and the worktree interface gains `diff(path)` for the diff gate. Without a patcher, COMPLEX findings are left for humans.

**Design note (reflected in spec §5.5):** the Claude tool-use loop runs **in the worker**. The sandbox container only executes the tool calls (file read/write inside `/work`, allow-listed commands). The sandbox therefore needs **no Anthropic key** and egress only to the package registry.

**Files:**
- Create: `backend/research/diff_gate.py` — `ChangedFile(path, added_lines, removed_lines, added_text)`, `check_diff(files) -> None` (raises `DiffRejected(reason)`)
- Create: `backend/research/sandbox.py` — `build_sandbox_command(worktree: Path, image: str) -> list[str]`, `SandboxTools(exec_in_sandbox, allowed_commands)` with `dispatch(tool_name, args)`, `run_patch_loop(finding, *, client, tools, max_iterations=30, deadline_s=900) -> list[ChangedFile]`
- Modify: `backend/research/pr_engine.py` — case 3: `COMPLEX` without bot PR → sandbox → diff gate → Draft-PR labelled `patchbot:ai-generated`; case 1 + `COMPLEX` → companion Draft-PR based on the bot branch
- Create: `backend/research/tests/test_diff_gate.py`, `backend/research/tests/test_sandbox.py`

**Tests:**

```python
# backend/research/tests/test_diff_gate.py
import pytest
from research.diff_gate import ChangedFile, DiffRejected, check_diff


def cf(path, added=1, removed=0, added_text="x = 1\n"):
    return ChangedFile(path=path, added_lines=added, removed_lines=removed, added_text=added_text)


@pytest.mark.parametrize(
    "path",
    [".github/workflows/ci.yml", ".circleci/config.yml", "deploy/compose.yaml", "docker-compose.prod.yml",
     "infra/main.tf", ".env.production", "config/.env", "k8s/deployment.yaml"],
)
def test_denied_paths(path):
    with pytest.raises(DiffRejected):
        check_diff([cf(path)])


@pytest.mark.parametrize(
    "secret",
    ["AKIAABCDEFGHIJKLMNOP", "-----BEGIN RSA PRIVATE KEY-----", "ghp_" + "a" * 36, "xoxb-123-456-abc"],
)
def test_secret_patterns(secret):
    with pytest.raises(DiffRejected):
        check_diff([cf("src/app.ts", added_text=f"const k = '{secret}';\n")])


def test_size_limit():
    with pytest.raises(DiffRejected):
        check_diff([cf("src/a.ts", added=300, removed=201)])


def test_accepts_normal_code_and_dockerfile_changes():
    check_diff([cf("src/report.ts", added=12, removed=4), cf("Dockerfile", added=1, removed=1)])
```

```python
# backend/research/tests/test_sandbox.py
from pathlib import Path
import pytest
from research.sandbox import SandboxTools, ToolRejected, build_sandbox_command


def test_sandbox_command_has_no_secrets_and_restricted_network():
    cmd = build_sandbox_command(Path("/var/patchbot/wt/abc"), image="patchbot-sandbox:node22")
    joined = " ".join(cmd)
    assert "--network=patchbot-sandbox-egress" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges" in cmd
    assert "/var/patchbot/wt/abc:/work:rw" in joined
    for forbidden in ("ANTHROPIC", "GITHUB", "AWS_", "SLACK", "/var/run/docker.sock"):
        assert forbidden not in joined


class FakeExec:
    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        return (0, "ok", "")


def test_tools_confine_paths_to_work_dir():
    tools = SandboxTools(exec_in_sandbox=FakeExec(), allowed_commands=[["npm", "test"]])
    with pytest.raises(ToolRejected):
        tools.dispatch("read_file", {"path": "../../etc/passwd"})
    with pytest.raises(ToolRejected):
        tools.dispatch("write_file", {"path": "/etc/hosts", "content": "x"})


def test_tools_only_run_allowlisted_commands():
    exec_ = FakeExec()
    tools = SandboxTools(exec_in_sandbox=exec_, allowed_commands=[["npm", "test"], ["npm", "ci", "--ignore-scripts"]])
    tools.dispatch("run_command", {"argv": ["npm", "test"]})
    with pytest.raises(ToolRejected):
        tools.dispatch("run_command", {"argv": ["curl", "https://evil.example"]})
    with pytest.raises(ToolRejected):
        tools.dispatch("run_command", {"argv": ["npm", "test", "&&", "rm", "-rf", "/"]})
    assert exec_.calls == [["npm", "test"]]
```

Add pr-engine tests in `test_pr_engine.py` with a `FakeSandbox` returning a canned diff:
- rejected diff → no PR, finding stays `COMPLEX`, the `FindingEvent` note contains the rejection reason;
- accepted diff → Draft-PR with label `patchbot:ai-generated`, `pr_source == "PATCHBOT_AI"`, pushed by Patchbot to `patchbot/…`;
- `COMPLEX` finding with a bot PR → companion Draft-PR with `base == <bot head_ref>`; no push to the bot branch.

**Commit:** `feat(research): add sandboxed Claude code patching with diff gate and AI-labelled Draft-PRs`

---

### Task 19: Maintenance updates (non-CVE bot PRs)

**Spec:** §5.2 (routine maintenance), §5.6.

**Files:**
- Modify: `backend/research/models.py` — `MaintenanceUpdate` (fields per §5.6)
- Create: `backend/research/maintenance.py` — `sync_maintenance_updates(*, github) -> dict`, `request_analysis(update, *, github, client) -> None`
- Create: `backend/research/tests/test_maintenance.py`

**Tests:**

```python
# backend/research/tests/test_maintenance.py
import pytest
from research.maintenance import sync_maintenance_updates
from research.models import MaintenanceUpdate
from testing.factories import make_finding, make_project, make_repo
from testing.fakes import FakeGitHub

REPO = "westcoder/materialdatenbank"


def bot_pr(number, title):
    return {"number": number, "html_url": f"u{number}", "user_login": "renovate[bot]",
            "head_ref": f"renovate/{number}", "title": title, "draft": False}


@pytest.mark.django_db
def test_non_cve_bot_prs_become_maintenance_updates():
    repo = make_repo(full_name=REPO, project=make_project(slug="wuerth"))
    make_finding(repository=repo, project=repo.project, package_name="lodash", pr_number=41, state="NEW")
    gh = FakeGitHub(pulls={REPO: [
        bot_pr(41, "Update dependency lodash to v4.17.21"),
        bot_pr(42, "Update dependency eslint to v9.2.0"),
        bot_pr(43, "Update dependency typescript to v6"),
    ]})
    sync_maintenance_updates(github=gh)
    updates = {u.package_name: u for u in MaintenanceUpdate.objects.all()}
    assert set(updates) == {"eslint", "typescript"}
    assert updates["typescript"].update_type == "MAJOR"


@pytest.mark.django_db
def test_closed_bot_prs_are_removed():
    make_repo(full_name=REPO, project=make_project(slug="wuerth"))
    sync_maintenance_updates(github=FakeGitHub(pulls={REPO: [bot_pr(42, "Update dependency eslint to v9.2.0")]}))
    sync_maintenance_updates(github=FakeGitHub(pulls={REPO: []}))
    assert MaintenanceUpdate.objects.count() == 0
```

**Commit:** `feat(research): list non-CVE Renovate/Dependabot PRs as quiet maintenance updates`

---

## Phase 4 — Triage Runtime

### Task 20: Live verification

**Spec:** §6.4.

**Files:**
- Create: `backend/triage/verification.py` — `verify_findings(*, github, image_scan_lookup, now=None) -> list[Finding]`, `needs_deployment_decision(finding) -> bool`. `image_scan_lookup(digest_ref) -> dict | None` returns the cached scan (`{"status", "vulnerabilities"}`), injected by `research` so `triage` does not import it.
- Create: `backend/triage/tests/test_verification.py`

**Tests:**

```python
# backend/triage/tests/test_verification.py
from datetime import datetime, timedelta, timezone
import pytest
from triage.verification import needs_deployment_decision, verify_findings
from testing.factories import make_container, make_finding, make_host, make_project, make_repo
from testing.fakes import FakeGitHub

MERGED = datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
NOW = MERGED + timedelta(hours=3)
REPO = "westcoder/materialdatenbank"


@pytest.fixture
def setup(db):
    project = make_project(slug="wuerth")
    repo = make_repo(full_name=REPO, project=project, deployment_mode="CONTAINER")
    finding = make_finding(repository=repo, project=project, state="PR_MERGED_WAITING_LIVE",
                           merge_commit_sha="m1", pr_merged_at=MERGED, package_name="lodash",
                           vulnerability_ids=["CVE-2026-0001"])
    return project, repo, finding


def container(project, repo, *, seen=NOW, slug="mdb", **kw):
    host = make_host(slug=slug, project=project, last_seen_at=seen)
    return make_container(host, project=project, repository=repo, **kw)


def no_scan(digest):
    return None


def test_no_linked_container_never_verifies(setup):
    _, _, f = setup
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    f.refresh_from_db()
    assert f.state == "PR_MERGED_WAITING_LIVE"


def test_stale_telemetry_never_verifies(setup):
    project, repo, f = setup
    container(project, repo, seen=MERGED - timedelta(minutes=5), oci_revision="r2")
    verify_findings(github=FakeGitHub(compare={(REPO, "m1", "r2"): "ahead"}), image_scan_lookup=no_scan, now=NOW)
    f.refresh_from_db()
    assert f.state == "PR_MERGED_WAITING_LIVE"


def test_revision_proof_verifies(setup):
    project, repo, f = setup
    container(project, repo, oci_revision="r2")
    verify_findings(github=FakeGitHub(compare={(REPO, "m1", "r2"): "ahead"}), image_scan_lookup=no_scan, now=NOW)
    f.refresh_from_db()
    assert f.state == "VERIFIED_LIVE"
    assert f.verified_live_at == NOW


def test_build_timestamp_alone_is_not_proof(setup):
    project, repo, f = setup
    container(project, repo, oci_revision="old", image_created_at=MERGED + timedelta(minutes=30))
    verify_findings(github=FakeGitHub(compare={(REPO, "m1", "old"): "behind"}), image_scan_lookup=no_scan, now=NOW)
    f.refresh_from_db()
    assert f.state == "PR_MERGED_WAITING_LIVE"


def test_every_linked_container_must_be_proven(setup):
    project, repo, f = setup
    container(project, repo, slug="mdb", oci_revision="r2")
    container(project, repo, slug="converter", oci_revision="old")
    gh = FakeGitHub(compare={(REPO, "m1", "r2"): "ahead", (REPO, "m1", "old"): "behind"})
    verify_findings(github=gh, image_scan_lookup=no_scan, now=NOW)
    f.refresh_from_db()
    assert f.state == "PR_MERGED_WAITING_LIVE"


def test_checkout_proof_for_host_checkout_repos(setup):
    project, repo, f = setup
    repo.deployment_mode = "HOST_CHECKOUT"
    repo.save()
    container(project, repo, git_head_sha="m1")
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    f.refresh_from_db()
    assert f.state == "VERIFIED_LIVE"


def test_scan_proof_verifies(setup):
    project, repo, f = setup
    container(project, repo, oci_revision="", repo_digests=["ecr/mdb@sha256:new"])
    clean = {"status": "OK", "vulnerabilities": []}
    verify_findings(github=FakeGitHub(), image_scan_lookup=lambda d: clean if d.endswith("new") else None, now=NOW)
    f.refresh_from_db()
    assert f.state == "VERIFIED_LIVE"


def test_unknown_deployment_mode_without_containers_asks_for_decision(setup):
    _, repo, f = setup
    repo.deployment_mode = "UNKNOWN"
    repo.save()
    assert needs_deployment_decision(f) is True


@pytest.mark.django_db
@pytest.mark.parametrize(
    "installed,apt_age_h,reboot,expected",
    [
        ("1.1.1f-1ubuntu2.23", 2, False, "VERIFIED_LIVE"),
        ("1.1.1f-1ubuntu2.22", 2, False, "IN_PROGRESS"),
        ("1.1.1f-1ubuntu2.23", 30, False, "IN_PROGRESS"),
        ("1.1.1f-1ubuntu2.23", 2, True, "IN_PROGRESS"),
    ],
)
def test_apt_verification(installed, apt_age_h, reboot, expected):
    host = make_host(slug="mdb", last_seen_at=NOW, reboot_required=reboot,
                     apt_lists_updated_at=NOW - timedelta(hours=apt_age_h))
    host.packages.create(name="openssl", installed_version=installed, candidate_version="", is_security_update=False)
    f = make_finding(layer="INFRASTRUCTURE", host=host, ecosystem="deb", package_name="openssl",
                     target_version="1.1.1f-1ubuntu2.23", state="IN_PROGRESS", acknowledged_at=NOW - timedelta(hours=5))
    verify_findings(github=FakeGitHub(), image_scan_lookup=no_scan, now=NOW)
    f.refresh_from_db()
    assert f.state == expected
```

**Commit:** `feat(triage): verify live rollouts via revision, checkout or image-scan proof with fresh telemetry`

---

### Task 21: Dismissal, snooze and reopen rules

**Spec:** §6.5, §6.2 (reopen rows).

**Files:**
- Create: `backend/triage/dismissal.py` — `dismiss(finding, actor, *, mode, reason, snooze_days=14, source, slack, now=None)`, `reopen(finding, actor, *, source, note, now=None)`, `evaluate_reopen_rules(*, now=None) -> list[Finding]`
- Modify: `backend/triage/models.py` — `dismissed_at`, `dismissed_severity`, `dismissed_kev_listed` (snapshot for the reopen rules)
- Extend: `backend/testing/fakes.py` — `FakeSlack(fail=False)` (records `messages: list[(channel, text, blocks)]`; raises `SlackError` when `fail=True`)
- Create: `backend/triage/tests/test_dismissal.py`

**Tests:**

```python
# backend/triage/tests/test_dismissal.py
from datetime import datetime, timedelta, timezone
import pytest
from django.core.exceptions import ValidationError
from triage.dismissal import dismiss, evaluate_reopen_rules, reopen
from testing.factories import make_finding, make_member
from testing.fakes import FakeSlack

NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)
REASON = "Nur im Build-Container genutzt, nicht im Runtime-Image."


@pytest.fixture
def actor(db):
    return make_member(email="dev@westcode.de", slack_user_id="U3")


def test_reason_is_mandatory(actor):
    with pytest.raises(ValidationError):
        dismiss(make_finding(), actor, mode="DISMISSED", reason="passt", source="WEB", slack=FakeSlack(), now=NOW)


@pytest.mark.parametrize("severity,posts", [("CRITICAL", 1), ("HIGH", 1), ("MEDIUM", 0)])
def test_transparency_post_for_high_and_critical(actor, settings, severity, posts):
    settings.SLACK_TEAM_CHANNEL_ID = "C-TEAM"
    slack = FakeSlack()
    f = make_finding(highest_severity=severity)
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=slack, now=NOW)
    assert f.state == "DISMISSED"
    assert len(slack.messages) == posts
    if posts:
        channel, text, blocks = slack.messages[0]
        assert channel == "C-TEAM"
        assert REASON in text
        assert any(el.get("action_id") == "reopen" for b in blocks for el in b.get("elements", []))


def test_snooze_sets_until_and_reopens_on_expiry(actor):
    f = make_finding(highest_severity="MEDIUM")
    dismiss(f, actor, mode="SNOOZED", reason=REASON, snooze_days=14, source="WEB", slack=FakeSlack(), now=NOW)
    assert f.snoozed_until == NOW + timedelta(days=14)
    evaluate_reopen_rules(now=NOW + timedelta(days=14, minutes=1))
    f.refresh_from_db()
    assert f.state == "NEW"


@pytest.mark.parametrize("change", [{"highest_severity": "CRITICAL"}, {"kev_listed": True}])
def test_dismissed_reopens_when_risk_rises(actor, change):
    f = make_finding(highest_severity="HIGH", kev_listed=False)
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=FakeSlack(), now=NOW)
    for key, value in change.items():
        setattr(f, key, value)
    f.save()
    evaluate_reopen_rules(now=NOW)
    f.refresh_from_db()
    assert f.state == "NEW"


def test_dismissed_reopens_after_180_days(actor):
    f = make_finding(highest_severity="MEDIUM")
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=FakeSlack(), now=NOW)
    evaluate_reopen_rules(now=NOW + timedelta(days=181))
    f.refresh_from_db()
    assert f.state == "NEW"


def test_reopen_button_by_any_member(actor):
    other = make_member(email="other@westcode.de")
    f = make_finding(highest_severity="HIGH")
    dismiss(f, actor, mode="DISMISSED", reason=REASON, source="WEB", slack=FakeSlack(), now=NOW)
    reopen(f, other, source="SLACK", note="Bitte nochmal prüfen", now=NOW)
    assert f.state == "NEW"
    assert f.events.filter(actor=other, source="SLACK", to_state="NEW").exists()
```

**Commit:** `feat(triage): add dismissal and snooze with transparency post and automatic reopen rules`

---

### Task 22: Slack client, aggregated DMs and idempotent escalation

**Spec:** §6.6.

**Files:**
- Create: `backend/triage/slack.py` — `SlackClient(token)` with `post_message(channel, text, blocks)` (a user ID as channel posts into the app DM), `lookup_user_by_email(email)`; raises `SlackError`
- Modify: `backend/triage/models.py` — `NotificationLog` (unique `(finding, kind, stage, recipient)`), `IntegrationHealth(name pk, ok, last_error, checked_at)`
- Create: `backend/triage/notifications.py` — `send_new_finding_dms(*, slack, now=None) -> int`, `escalate_overdue(*, slack, now=None) -> int`, `sync_slack_user_ids(*, slack) -> int`
- Create: `backend/triage/tests/test_notifications.py`

**Tests:**

```python
# backend/triage/tests/test_notifications.py
from datetime import datetime
from zoneinfo import ZoneInfo
import pytest
from triage.models import IntegrationHealth, NotificationLog
from triage.notifications import escalate_overdue, send_new_finding_dms
from testing.factories import make_finding, make_member
from testing.fakes import FakeSlack

BER = ZoneInfo("Europe/Berlin")
MONDAY_9 = datetime(2026, 11, 9, 9, 0, tzinfo=BER)
SATURDAY_10 = datetime(2026, 11, 7, 10, 0, tzinfo=BER)


@pytest.fixture
def team(db, settings):
    settings.SLACK_TEAM_CHANNEL_ID = "C-TEAM"
    return make_member(email="a@westcode.de", slack_user_id="UA"), make_member(email="b@westcode.de", slack_user_id="UB")


def test_one_aggregated_dm_per_assignee(team):
    a, b = team
    for _ in range(3):
        make_finding(state="NEW", assignee=a, triage_status="TRIAGED")
    make_finding(state="NEW", assignee=b, triage_status="TRIAGED")
    slack = FakeSlack()
    assert send_new_finding_dms(slack=slack, now=MONDAY_9) == 2
    dm_a = next(m for m in slack.messages if m[0] == "UA")
    assert sum(1 for blk in dm_a[2] if blk["type"] == "actions") == 3


def test_dms_are_not_resent(team):
    a, _ = team
    make_finding(state="NEW", assignee=a)
    slack = FakeSlack()
    send_new_finding_dms(slack=slack, now=MONDAY_9)
    send_new_finding_dms(slack=slack, now=MONDAY_9)
    assert len(slack.messages) == 1


def test_filtered_findings_are_never_sent(team):
    a, _ = team
    make_finding(state="FILTERED_IRRELEVANT", assignee=a)
    assert send_new_finding_dms(slack=FakeSlack(), now=MONDAY_9) == 0


def test_unassigned_goes_to_team_channel(team):
    make_finding(state="NEW", assignee=None)
    slack = FakeSlack()
    send_new_finding_dms(slack=slack, now=MONDAY_9)
    assert slack.messages[0][0] == "C-TEAM"


def test_escalation_posts_once_per_stage(team):
    a, _ = team
    f = make_finding(state="NEW", assignee=a, deadline_at=datetime(2026, 11, 9, 7, 0, tzinfo=BER))
    slack = FakeSlack()
    assert escalate_overdue(slack=slack, now=MONDAY_9) == 1
    assert escalate_overdue(slack=slack, now=MONDAY_9) == 0
    f.refresh_from_db()
    assert f.escalated_stage == 1
    assert "<@UA>" in slack.messages[0][1]


def test_escalation_waits_for_posting_window(team):
    a, _ = team
    make_finding(state="NEW", assignee=a, deadline_at=datetime(2026, 11, 7, 7, 0, tzinfo=BER))
    assert escalate_overdue(slack=FakeSlack(), now=SATURDAY_10) == 0


def test_kev_critical_escalates_immediately(team):
    a, _ = team
    make_finding(state="NEW", assignee=a, highest_severity="CRITICAL", kev_listed=True,
                 deadline_at=datetime(2026, 11, 7, 7, 0, tzinfo=BER))
    assert escalate_overdue(slack=FakeSlack(), now=SATURDAY_10) == 1


def test_slack_failure_is_retried_and_recorded(team):
    a, _ = team
    make_finding(state="NEW", assignee=a)
    assert send_new_finding_dms(slack=FakeSlack(fail=True), now=MONDAY_9) == 0
    assert NotificationLog.objects.count() == 0
    assert IntegrationHealth.objects.get(name="slack").ok is False
    assert send_new_finding_dms(slack=FakeSlack(), now=MONDAY_9) == 1
    assert IntegrationHealth.objects.get(name="slack").ok is True
```

**Commit:** `feat(triage): send aggregated Slack DMs and idempotent working-hour escalations`

---

### Task 23: Signed public webhooks (Slack, GitHub) and PR reconciliation

**Spec:** §3.3 (public ingress), §6.1 (PR merge detection), §7.3.

**Files:**
- Modify: `backend/triage/models.py` — `WebhookEvent(source, delivery_id unique nullable, payload, received_at, status: PENDING|PROCESSED|REJECTED, error)`
- Create: `backend/triage/webhooks.py` — plain Django views (`csrf_exempt`, read `request.body` before any parsing) `slack_interactions`, `github_webhook`; `process_webhook_event(event, *, github, slack, now=None)`; `reconcile_open_prs(*, github, now=None) -> int`
- Modify: `backend/config/urls.py` — `api/webhooks/slack/interactions/`, `api/webhooks/github/`
- Modify: `backend/config/settings.py` — `SLACK_SIGNING_SECRET`, `GITHUB_WEBHOOK_SECRET`
- Create: `backend/triage/tests/test_webhooks.py`

**Tests:**

```python
# backend/triage/tests/test_webhooks.py
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlencode
import pytest
from rest_framework.test import APIClient
from triage.models import WebhookEvent
from triage.webhooks import process_webhook_event, reconcile_open_prs
from testing.factories import make_finding, make_member
from testing.fakes import FakeGitHub, FakeSlack

SLACK_SECRET = "slack-secret"
GH_SECRET = "gh-secret"
SLACK_PATH = "/api/webhooks/slack/interactions/"
GH_PATH = "/api/webhooks/github/"
NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def secrets(settings):
    settings.SLACK_SIGNING_SECRET = SLACK_SECRET
    settings.GITHUB_WEBHOOK_SECRET = GH_SECRET


def slack_sig(ts, body):
    return "v0=" + hmac.new(SLACK_SECRET.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()


def post_slack(payload, *, ts=None, sig=None):
    ts = str(ts or int(time.time()))
    body = urlencode({"payload": json.dumps(payload)})
    client = APIClient(enforce_csrf_checks=True)
    return client.generic("POST", SLACK_PATH, body, content_type="application/x-www-form-urlencoded",
                          HTTP_X_SLACK_REQUEST_TIMESTAMP=ts, HTTP_X_SLACK_SIGNATURE=sig or slack_sig(ts, body))


def post_github(payload, *, delivery="d-1", sig=None, event="pull_request"):
    body = json.dumps(payload)
    signature = sig or "sha256=" + hmac.new(GH_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    client = APIClient(enforce_csrf_checks=True)
    return client.generic("POST", GH_PATH, body, content_type="application/json",
                          HTTP_X_HUB_SIGNATURE_256=signature, HTTP_X_GITHUB_DELIVERY=delivery, HTTP_X_GITHUB_EVENT=event)


def ack_payload(finding_id, slack_user="UA"):
    return {"type": "block_actions", "user": {"id": slack_user},
            "actions": [{"action_id": "ack", "value": str(finding_id)}]}


@pytest.mark.django_db
def test_slack_valid_signature_is_enqueued_without_session_or_csrf():
    assert post_slack(ack_payload(1)).status_code == 200
    assert WebhookEvent.objects.get().source == "SLACK"


@pytest.mark.django_db
def test_slack_invalid_signature_rejected():
    assert post_slack(ack_payload(1), sig="v0=deadbeef").status_code == 401
    assert WebhookEvent.objects.count() == 0


@pytest.mark.django_db
def test_slack_replayed_timestamp_rejected():
    assert post_slack(ack_payload(1), ts=int(time.time()) - 301).status_code == 401


@pytest.mark.django_db
def test_slack_ack_from_known_user_acknowledges():
    member = make_member(email="a@westcode.de", slack_user_id="UA")
    f = make_finding(state="NEW", assignee=member)
    post_slack(ack_payload(f.id, "UA"))
    process_webhook_event(WebhookEvent.objects.get(), github=FakeGitHub(), slack=FakeSlack(), now=NOW)
    f.refresh_from_db()
    assert f.state == "IN_PROGRESS"
    assert f.events.filter(source="SLACK").exists()


@pytest.mark.django_db
def test_slack_action_from_unknown_user_rejected():
    f = make_finding(state="NEW")
    post_slack(ack_payload(f.id, "U-STRANGER"))
    event = WebhookEvent.objects.get()
    process_webhook_event(event, github=FakeGitHub(), slack=FakeSlack(), now=NOW)
    f.refresh_from_db()
    event.refresh_from_db()
    assert f.state == "NEW"
    assert event.status == "REJECTED"


@pytest.mark.django_db
def test_github_invalid_signature_rejected():
    assert post_github({"action": "closed"}, sig="sha256=00").status_code == 401


@pytest.mark.django_db
def test_github_duplicate_delivery_is_ignored():
    post_github({"action": "closed"}, delivery="d-7")
    assert post_github({"action": "closed"}, delivery="d-7").status_code == 200
    assert WebhookEvent.objects.count() == 1


@pytest.mark.django_db
def test_github_processing_trusts_api_not_payload():
    f = make_finding(state="IN_PROGRESS", pr_number=41, repository__full_name="westcoder/mdb")
    payload = {"action": "closed", "repository": {"full_name": "westcoder/mdb"},
               "pull_request": {"number": 41, "merged": True, "merge_commit_sha": "forged"}}
    post_github(payload)
    gh = FakeGitHub(pull_details={("westcoder/mdb", 41): {"state": "open", "merged": False}})
    process_webhook_event(WebhookEvent.objects.get(), github=gh, slack=FakeSlack(), now=NOW)
    f.refresh_from_db()
    assert f.state == "IN_PROGRESS"


@pytest.mark.django_db
def test_reconciliation_poll_catches_missed_merge():
    f = make_finding(state="IN_PROGRESS", pr_number=41, repository__full_name="westcoder/mdb")
    gh = FakeGitHub(pull_details={("westcoder/mdb", 41): {
        "state": "closed", "merged": True, "merged_at": "2026-11-09T08:00:00Z", "merge_commit_sha": "m1"}})
    assert reconcile_open_prs(github=gh, now=NOW) == 1
    f.refresh_from_db()
    assert (f.state, f.merge_commit_sha) == ("PR_MERGED_WAITING_LIVE", "m1")
```

**Commit:** `feat(triage): add signature-verified Slack and GitHub webhooks with PR reconciliation fallback`

---

### Task 24: Status-Ampel and Control Plane REST API

**Spec:** §6.7, §7.1 (actor from session), §8 (data needs).

**Files:**
- Create: `backend/triage/ampel.py` — `compute_ampel(*, now=None) -> dict` (`color: GREY|RED|YELLOW|GREEN`, `label_de`, `causes: list[str]`, `counts`)
- Create: `backend/triage/serializers.py`, `backend/triage/api.py`
- Modify: `backend/config/urls.py`
- Create: `backend/triage/tests/test_ampel.py`, `backend/triage/tests/test_api.py`

**Endpoints:**

| Method & path | Permission | Notes |
|---|---|---|
| `GET /api/dashboard/` | member | `ampel`, `buckets.simple`, `buckets.complex`, `buckets.waiting_live`, `maintenance`, `filtered` |
| `GET /api/findings/<id>/` | member | includes `events`, `verification` rows (proof per container, `image_created_at` as hint), `needs_deployment_decision` |
| `POST /api/findings/<id>/acknowledge/` | member | actor = `request.user.team_member` |
| `POST /api/findings/<id>/dismiss/` | member | `{mode, reason, snooze_days?}`; actor fields in the body are ignored |
| `POST /api/findings/<id>/reopen/` | member | |
| `POST /api/findings/<id>/extend/` | member | `{reason}` |
| `POST /api/maintenance/<id>/request-analysis/` | member | enqueues job |
| `GET /api/triage-projects/` | member | projects + `unassigned_assets` |
| `POST /api/triage-projects/sync-notion/` | admin | enqueues job |
| `POST /api/triage-projects/<slug>/monitoring/` | admin | `{monitored}` |
| `POST /api/assets/<type>/<id>/confirm-suggestion/` | admin | |
| `POST /api/assets/<type>/<id>/assign/` | admin | `{project_slug}` |
| `PATCH /api/repositories/<id>/` | admin | `deployment_mode` |
| `GET/POST /api/team/`, `PATCH /api/team/<id>/`, `POST /api/team/<id>/test-dm/` | GET member, rest admin | |
| `POST /api/scans/run/` | member | `202`; `409` if a scan job is queued or running |

**Tests:**

```python
# backend/triage/tests/test_ampel.py
from datetime import datetime, timedelta, timezone
import pytest
from research.models import ScanRun
from triage.ampel import compute_ampel
from triage.models import IntegrationHealth
from testing.factories import make_finding, make_host, make_member, make_project

NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def healthy(db):
    ScanRun.objects.create(status="OK", trigger="SCHEDULED",
                           started_at=NOW - timedelta(hours=2), finished_at=NOW - timedelta(hours=2))
    make_host(slug="mdb", project=make_project(slug="wuerth", is_monitored=True), last_seen_at=NOW - timedelta(minutes=10))


def test_grey_without_successful_scan(db):
    assert compute_ampel(now=NOW)["color"] == "GREY"


def test_grey_when_last_scan_too_old(healthy):
    ScanRun.objects.update(finished_at=NOW - timedelta(hours=27))
    assert compute_ampel(now=NOW)["color"] == "GREY"


def test_grey_when_agent_stale(healthy):
    make_host(slug="stale", project=make_project(slug="ses", is_monitored=True), last_seen_at=NOW - timedelta(minutes=61))
    ampel = compute_ampel(now=NOW)
    assert ampel["color"] == "GREY"
    assert any("stale" in c for c in ampel["causes"])


def test_grey_when_slack_failing(healthy):
    IntegrationHealth.objects.create(name="slack", ok=False, last_error="invalid_auth", checked_at=NOW)
    assert compute_ampel(now=NOW)["color"] == "GREY"


def test_red_for_new_finding(healthy):
    make_finding(state="NEW", assignee=make_member(email="a@westcode.de"), deadline_at=NOW + timedelta(hours=5))
    assert compute_ampel(now=NOW)["color"] == "RED"


def test_red_for_overdue(healthy):
    make_finding(state="IN_PROGRESS", assignee=make_member(email="a@westcode.de"), deadline_at=NOW - timedelta(minutes=1))
    assert compute_ampel(now=NOW)["color"] == "RED"


def test_yellow_when_all_acknowledged_in_time(healthy):
    make_finding(state="IN_PROGRESS", assignee=make_member(email="a@westcode.de"), deadline_at=NOW + timedelta(days=1))
    assert compute_ampel(now=NOW)["color"] == "YELLOW"


def test_green_when_nothing_open(healthy):
    make_finding(state="VERIFIED_LIVE")
    make_finding(state="FILTERED_IRRELEVANT")
    assert compute_ampel(now=NOW)["color"] == "GREEN"
```

```python
# backend/triage/tests/test_api.py
import pytest
from rest_framework.test import APIClient
from triage.models import Finding
from testing.factories import make_finding, make_member, make_project, make_user_with_member


@pytest.fixture
def member_client(db):
    user, member = make_user_with_member(email="dev@westcode.de", slack_user_id="U3")
    client = APIClient()
    client.force_login(user)
    return client, member


def test_dashboard_requires_login(db):
    assert APIClient().get("/api/dashboard/").status_code == 403


def test_dashboard_buckets(member_client):
    client, member = member_client
    make_finding(state="NEW", complexity="SIMPLE", assignee=member)
    make_finding(state="IN_PROGRESS", complexity="COMPLEX", assignee=member)
    make_finding(state="PR_MERGED_WAITING_LIVE", assignee=member)
    body = client.get("/api/dashboard/").json()
    assert [len(body["buckets"][k]) for k in ("simple", "complex", "waiting_live")] == [1, 1, 1]
    assert body["ampel"]["color"] in {"RED", "GREY"}


def test_acknowledge_uses_session_user_not_body(member_client):
    client, member = member_client
    other = make_member(email="other@westcode.de")
    f = make_finding(state="NEW", assignee=other)
    resp = client.post(f"/api/findings/{f.id}/acknowledge/", {"actor_id": other.id}, format="json")
    assert resp.status_code == 200
    f.refresh_from_db()
    assert f.assignee == member


def test_dismiss_validates_reason_and_records_session_actor(member_client):
    client, member = member_client
    f = make_finding(state="NEW", highest_severity="MEDIUM")
    short = client.post(f"/api/findings/{f.id}/dismiss/", {"mode": "DISMISSED", "reason": "kurz"}, format="json")
    assert short.status_code == 400
    resp = client.post(f"/api/findings/{f.id}/dismiss/",
                       {"mode": "DISMISSED", "reason": "Nur im Test-Setup genutzt, nicht deployed.", "dismissed_by": 999},
                       format="json")
    assert resp.status_code == 200
    assert Finding.objects.get(id=f.id).dismissed_by == member


def test_monitoring_toggle_is_admin_only(member_client):
    client, _ = member_client
    make_project(slug="wuerth")
    resp = client.post("/api/triage-projects/wuerth/monitoring/", {"monitored": False}, format="json")
    assert resp.status_code == 403


def test_scan_run_conflict_while_running(member_client):
    client, _ = member_client
    assert client.post("/api/scans/run/").status_code == 202
    assert client.post("/api/scans/run/").status_code == 409
```

**Commit:** `feat(api): add Status-Ampel with grey data-health state and the v2 control plane endpoints`

---

### Task 25: Worker, scheduler and scan pipeline

**Spec:** §3.3.

**Files:**
- Modify: `backend/triage/models.py` — `Job` (`kind`, `payload`, `status`, `run_after`, `locked_at`, `attempts`, `last_error`), `ScheduleState(kind pk, last_run_at)`
- Create: `backend/triage/jobs.py` — `enqueue(kind, payload=None, *, unique=False) -> Job | None`, `claim_next(now) -> Job | None` (`select_for_update(skip_locked=True)` on PostgreSQL)
- Create: `backend/triage/schedule.py` — `SCHEDULE` and `due_jobs(now, last_runs) -> list[str]`
- Create: `backend/research/pipeline.py` — `run_scan(*, github, trivy, llm, slack, bumper, worktrees, sandbox=None, now=None) -> ScanRun`; order: `sync_repositories` → `link_containers_to_repositories` → `suggest_projects` → `collect_and_upsert` → `apply_signals` → `apply_triage` → `assign` → `ensure_pr` → `sync_maintenance_updates` → `verify_findings` → `send_new_finding_dms` → `finalize_scan_run`
- Create: management commands `run_worker`, `run_scan_once`, `seed_dev` (refuses unless `DEBUG=True`; demo data never in production)
- Create: `backend/triage/tests/test_schedule.py`, `backend/research/tests/test_pipeline.py`

**Schedule:** `signals_refresh` 06:30, `notion_sync` 06:45, `slack_user_sync` 06:50, `daily_scan` 07:00 (Europe/Berlin, once per day each); `grace_eval` (escalation + reopen rules) every 15 min; `pr_reconcile` every 60 min; `process_webhooks` continuously.

**Tests:**

```python
# backend/triage/tests/test_schedule.py
from datetime import datetime
from zoneinfo import ZoneInfo
from triage.schedule import due_jobs

BER = ZoneInfo("Europe/Berlin")


def test_daily_scan_due_once_after_0700():
    assert "daily_scan" not in due_jobs(datetime(2026, 11, 9, 6, 59, tzinfo=BER), {})
    assert "daily_scan" in due_jobs(datetime(2026, 11, 9, 7, 0, tzinfo=BER), {})
    last = {"daily_scan": datetime(2026, 11, 9, 7, 0, tzinfo=BER)}
    assert "daily_scan" not in due_jobs(datetime(2026, 11, 9, 15, 0, tzinfo=BER), last)
    assert "daily_scan" in due_jobs(datetime(2026, 11, 10, 7, 1, tzinfo=BER), last)


def test_grace_eval_every_15_minutes():
    last = {"grace_eval": datetime(2026, 11, 9, 9, 0, tzinfo=BER)}
    assert "grace_eval" not in due_jobs(datetime(2026, 11, 9, 9, 14, tzinfo=BER), last)
    assert "grace_eval" in due_jobs(datetime(2026, 11, 9, 9, 15, tzinfo=BER), last)
```

```python
# backend/research/tests/test_pipeline.py
from datetime import datetime, timezone
import pytest
from research.pipeline import run_scan
from research.trivy import TrivyResult
from triage.models import Finding
from testing.factories import make_member, make_project, make_repo
from testing.fakes import FakeGitHub, FakeLLM, FakeSlack

NOW = datetime(2026, 11, 9, 6, 0, tzinfo=timezone.utc)
VULN = {"id": "CVE-2026-0001", "package": "lodash", "installed": "4.17.15", "fixed": "4.17.21", "severity": "HIGH",
        "ecosystem": "npm", "pkg_class": "lang-pkgs", "target": "package-lock.json"}
TRIAGE = {"reachability": "REACHABLE", "reachability_reason_category": "OTHER", "complexity": "SIMPLE",
          "confidence": 0.9, "summary_de": "Erreichbar.", "breaking_changes_de": "", "affected_files": []}


class Trivy:
    def scan_repo(self, full_name, path):
        return TrivyResult("OK", "", [VULN])

    def scan_image(self, ref):
        return TrivyResult("OK", "", [])


class Bumper:
    def bump(self, *args):
        return ["package.json", "package-lock.json"]


class Worktrees:
    def create(self, repo, base, branch):
        return f"/tmp/{branch}"


@pytest.mark.django_db
def test_end_to_end_scan_is_idempotent():
    owner = make_member(email="owner@westcode.de", slack_user_id="UO")
    make_repo(full_name="westcoder/mdb", project=make_project(slug="wuerth", owner=owner))
    gh = FakeGitHub(repos=[{"full_name": "westcoder/mdb", "default_branch": "main", "archived": False}])
    slack = FakeSlack()
    kwargs = dict(github=gh, trivy=Trivy(), llm=FakeLLM(tool_input=TRIAGE), slack=slack,
                  bumper=Bumper(), worktrees=Worktrees(), now=NOW)

    run_scan(**kwargs)
    run_scan(**kwargs)

    f = Finding.objects.get()
    assert (f.state, f.complexity, f.assignee, f.pr_source) == ("NEW", "SIMPLE", owner, "PATCHBOT")
    assert len(gh.created_pulls) == 1
    assert [m[0] for m in slack.messages] == ["UO"]
```

**Commit:** `feat(worker): add DB-backed job queue, scheduler and idempotent daily scan pipeline`

---

## Phase 5 — Frontend

All frontend tests use Vitest via `ng test`, `TestBed`, `provideHttpClient()` and `provideHttpClientTesting()`, following the existing `services-page.spec.ts` style. For tasks 27–30 the listed behaviours are the required test cases; write each `it(...)` fully with `HttpTestingController` flushes.

### Task 26: API client, auth bootstrap and CSRF

**Files:**
- Modify: `frontend/src/app/core/patchbot-api.ts` — DTOs `AmpelDto`, `DashboardDto`, `FindingDto`, `FindingDetailDto`, `VerificationRowDto`, `FindingEventDto`, `MaintenanceUpdateDto`, `TriageProjectDto`, `UnassignedAssetDto`, `TeamMemberDto`, `MeDto`; one method per endpoint of Task 24
- Create: `frontend/src/app/core/auth.ts` — `AuthService` (`me` signal, `load()`), `authGuard`, `LOGIN_REDIRECT` injection token (default `url => window.location.assign(url)`)
- Modify: `frontend/src/app/app.config.ts` — `provideHttpClient(withXsrfConfiguration({ cookieName: 'csrftoken', headerName: 'X-CSRFToken' }))`
- Create: `frontend/src/app/core/auth.spec.ts`

**Tests:**

```ts
// frontend/src/app/core/auth.spec.ts
import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withXsrfConfiguration } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AuthService, LOGIN_REDIRECT } from './auth';

describe('AuthService', () => {
  it('redirects to Entra login when /api/auth/me/ is rejected', async () => {
    const redirect = vi.fn();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: LOGIN_REDIRECT, useValue: redirect }],
    });
    const auth = TestBed.inject(AuthService);
    const http = TestBed.inject(HttpTestingController);
    const loading = auth.load();
    http.expectOne('/api/auth/me/').flush({ detail: 'nope' }, { status: 403, statusText: 'Forbidden' });
    await loading;
    expect(redirect).toHaveBeenCalledWith('/api/auth/entra/login/');
    expect(auth.me()).toBeNull();
  });

  it('stores the logged-in member', async () => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    const auth = TestBed.inject(AuthService);
    const http = TestBed.inject(HttpTestingController);
    const loading = auth.load();
    http.expectOne('/api/auth/me/').flush({ id: 1, name: 'Moritz Pietzschke', email: 'moritz.pietzschke@westcode.de', is_admin: true });
    await loading;
    expect(auth.me()?.is_admin).toBe(true);
  });
});

describe('CSRF', () => {
  it('sends X-CSRFToken from the csrftoken cookie on unsafe requests', () => {
    document.cookie = 'csrftoken=abc123';
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXsrfConfiguration({ cookieName: 'csrftoken', headerName: 'X-CSRFToken' })),
        provideHttpClientTesting(),
      ],
    });
    TestBed.inject(HttpClient).post('/api/scans/run/', {}).subscribe();
    const req = TestBed.inject(HttpTestingController).expectOne('/api/scans/run/');
    expect(req.request.headers.get('X-CSRFToken')).toBe('abc123');
  });
});
```

**Commit:** `feat(frontend): add v2 API client, Entra auth bootstrap and CSRF header`

---

### Task 27: Triage-Dashboard (Ampel, buckets, modes, filters)

**Spec:** §8.2.

**Files:**
- Create: `frontend/src/app/pages/triage-dashboard.ts`, `frontend/src/app/pages/triage-dashboard.spec.ts`
- Create: `frontend/src/app/components/ampel-banner.ts`
- Modify: `frontend/src/app/app.routes.ts` (`/` → `TriageDashboard`, guarded by `authGuard`), `frontend/src/app/app.ts` (nav: Triage-Dashboard, Projekte & Zuordnung, Live-Hosts, Team; user badge; „Scan & Sync starten“ disabled while a scan runs)

**Fixture and required cases:**

```ts
// frontend/src/app/pages/triage-dashboard.spec.ts (fixture)
const ME = { id: 7, name: 'Moritz Pietzschke', email: 'moritz.pietzschke@westcode.de', is_admin: false };
const DASHBOARD = {
  ampel: { color: 'GREY', label_de: 'Datenlage unvollständig', causes: ['Agent auf mdb.westcode.de seit 75 min stumm'], counts: {} },
  buckets: {
    simple: [{ id: 1, title: 'lodash 4.17.21', project_name: 'Würth', highest_severity: 'HIGH', state: 'NEW', assignee_id: 7 }],
    complex: [{ id: 2, title: 'django 6.0', project_name: 'SES Sandmann', highest_severity: 'CRITICAL', state: 'IN_PROGRESS', assignee_id: 9 }],
    waiting_live: [],
  },
  maintenance: [{ id: 5, package_name: 'eslint', target_version: '9.2.0', pr_url: 'https://github.com/westcoder/x/pull/1' }],
  filtered: [],
};
```

1. Renders the grey Ampel (`.ampel--grey`) with its cause text; renders red/yellow/green variants with their German labels.
2. Renders the three buckets with counts 1 / 1 / 0.
3. Switching to „Wartungs-Updates (ohne CVE)“ shows the maintenance row; „Automatisch gefiltert“ shows the empty state.
4. „Nur meine Aufgaben“ (me.id = 7) hides finding 2.
5. „Nach Projekt“ groups rows under „Würth“ and „SES Sandmann“.

**Commit:** `feat(frontend): add Triage-Dashboard with four-state Ampel, buckets, modes and filters`

---

### Task 28: Finding detail panel and actions

**Spec:** §8.2 (detail panel).

**Files:**
- Create: `frontend/src/app/components/finding-detail.ts`, `frontend/src/app/components/dismiss-dialog.ts`, `frontend/src/app/components/finding-detail.spec.ts`

**Required cases:**
1. „Ich bin dran“ posts to `/api/findings/1/acknowledge/` and re-renders with state `IN_PROGRESS`.
2. Dismiss dialog: submit disabled until the reason has ≥ 15 characters; then posts `{ mode, reason, snooze_days }`.
3. Verification table: one row per container with proof label („Revision“, „Checkout“, „Image-Scan“, „offen“); `image_created_at` shown with the label „Hinweis“, never as a proof.
4. `needs_deployment_decision` shows „Deployment-Art festlegen“ with a link to the repository in `/projects`.
5. Events list renders actor, source (Web/Slack/System) and transition.
6. Extend action requires a reason and is hidden after it was used in the current stage.

**Commit:** `feat(frontend): add finding detail panel with acknowledge, dismiss, extend and verification table`

---

### Task 29: Projekte & Zuordnung

**Spec:** §8.1.

**Files:**
- Modify: `frontend/src/app/pages/projects-page.ts`; create `frontend/src/app/pages/projects-page.spec.ts`

**Required cases:**
1. Unassigned inbox lists assets with suggestion; „Vorschlag übernehmen“ posts to `/api/assets/<type>/<id>/confirm-suggestion/` and removes the row.
2. Monitoring toggle and Notion sync button are only rendered for admins (`me.is_admin`).
3. `deployment_mode` select per repository patches `/api/repositories/<id>/`.
4. `notion_missing` projects show the badge „Nicht mehr in Notion“.

**Commit:** `feat(frontend): add project asset graph with unassigned inbox, monitoring toggle and deployment mode`

---

### Task 30: Live-Hosts and Team pages

**Spec:** §8.1.

**Files:**
- Modify: `frontend/src/app/pages/hosts-page.ts` (+ spec); create `frontend/src/app/pages/team-page.ts` (+ spec); route `/team`

**Required cases:**
1. Hosts tab label shows the dynamic count („Live-Hosts (n)“).
2. Hosts with telemetry older than 60 min get „Telemetrie veraltet“; apt lists older than 26 h get „apt-Listen veraltet“.
3. Container rows show digest, `oci_revision`, „Image gebaut am“ (`image_created_at`) and Git state.
4. Agent token generator only visible for admins.
5. Team page: admins can add/edit members (email must end with `@westcode.de`, validated client-side), toggle layers/admin/infra owner, and trigger „Test-DM senden“; non-admins see a read-only table.

**Commit:** `feat(frontend): show v2 host telemetry and add team directory page`

---

## Phase 6 — Cleanup & Rollout

### Task 31: Remove the v1 dashboard backend

**Spec:** §9 step 4.

**Files:**
- Move: `HostListView`, `HostDetailView`, `HostTokenGenerateView`, `serialize_host` from `backend/rollouts/api.py` to `backend/fleet/views.py` (serializer gains `kernel_version`, `project`, container `oci_source`/`image_created_at`/`git_head_sha`)
- Delete: `backend/catalog/` (incl. `live_sync.py`, `correlator.py`, `trivy.py`, `renovate_sync.py`) and `backend/rollouts/`
- Delete: v1 frontend `services-page.ts` and its spec
- Modify: `backend/config/urls.py`, settings, `pyproject.toml` testpaths
- Create: `backend/fleet/tests/test_v1_removed.py`

**Tests:**

```python
# backend/fleet/tests/test_v1_removed.py
import pytest
from django.urls import Resolver404, resolve


@pytest.mark.parametrize("path", ["/api/services/", "/api/sync/", "/api/projects/"])
def test_v1_dashboard_endpoints_removed(path):
    with pytest.raises(Resolver404):
        resolve(path)


@pytest.mark.parametrize("path", ["/api/hosts/", "/api/hosts/mdb/", "/api/hosts/mdb/token/"])
def test_host_endpoints_still_resolve(path):
    resolve(path)
```

Also run `cd frontend && npx ng build` (no dangling imports).

**Commit:** `refactor!: remove v1 catalog and rollouts apps after the v2 dashboard replacement`

---

### Task 32: Deployment topology and agent rollout runbook

**Spec:** §3.3, §9 steps 5–6, D-1.

**Files:**
- Modify: `deploy/compose.yaml` — services `web`, `worker`, `postgres`; network `patchbot-sandbox-egress` (`internal: true`; registry access only through an allow-listing egress proxy); volume `repo-cache`
- Create: `deploy/sandbox/Dockerfile.node22`, `deploy/sandbox/Dockerfile.python312` (non-root user, no credentials)
- Create: `docs/runbooks/patchbot-v2-rollout.md` covering:
  - reverse-proxy route exposing only `/api/webhooks/slack/interactions/` and `/api/webhooks/github/` (body limit 1 MB, rate limit)
  - Slack app config (interactivity URL, signing secret, scopes)
  - GitHub App creation (permissions per §3.2, org ruleset allowing pushes only to `patchbot/*`, webhook URL + secret, no access to `westcode-infra`)
  - ECR read role
  - staging-VM validation of the agent unit (`apt-get -s`, `docker inspect`, `git rev-parse` under `ProtectSystem=strict`)
  - fleet rollout order and rollback
  - CI change request for OCI labels `revision`/`source`
  - **worker Docker socket:** the worker starts sandbox containers and therefore has root-equivalent access on the Patchbot server; document this and evaluate rootless Docker or a dedicated sandbox host
- Modify: `backend/fleet/tests/test_deploy_config.py`

**Tests:**

```python
# backend/fleet/tests/test_deploy_config.py (add)
import yaml


def _env_keys(service: dict) -> list[str]:
    env = service.get("environment", {})
    return list(env) if isinstance(env, dict) else [e.split("=", 1)[0] for e in env]


def test_compose_has_web_worker_and_isolated_sandbox_network():
    compose = yaml.safe_load((REPO_ROOT / "deploy/compose.yaml").read_text())
    services = compose["services"]
    assert {"web", "worker", "postgres"} <= set(services)
    assert compose["networks"]["patchbot-sandbox-egress"]["internal"] is True
    for name in ("web", "postgres"):
        assert "/var/run/docker.sock" not in " ".join(services[name].get("volumes", []))
    assert "SLACK_APP_TOKEN" not in _env_keys(services["worker"])
    assert "SLACK_SIGNING_SECRET" in _env_keys(services["web"])
    assert "GITHUB_WEBHOOK_SECRET" in _env_keys(services["web"])
```

**Commit:** `chore(deploy): add v2 web/worker topology, sandbox images and rollout runbook`

---

## Review Focus (critical failure modes → guarding tests)

| Failure mode | Guarding test |
|---|---|
| Agent executes a server-supplied command | `test_main_only_posts_report_and_ignores_response`, `test_every_subprocess_call_is_read_only` |
| Broken scan shows green | `test_nonzero_exit_is_failed_not_clean`, `test_failed_target_keeps_existing_findings`, `test_grey_without_successful_scan` |
| Merged PR closed while old code runs | `test_build_timestamp_alone_is_not_proof`, `test_every_linked_container_must_be_proven`, `test_no_linked_container_never_verifies`, `test_stale_telemetry_never_verifies` |
| Claude hides a severe CVE | `test_policy_gate` (CRITICAL / KEV / EPSS / missing-evidence rows) |
| Prompt injection writes CI config or leaks secrets | `test_denied_paths`, `test_secret_patterns`, `test_sandbox_command_has_no_secrets_and_restricted_network`, `test_tools_only_run_allowlisted_commands` |
| Forged Slack/GitHub request changes a finding | `test_slack_invalid_signature_rejected`, `test_slack_replayed_timestamp_rejected`, `test_github_processing_trusts_api_not_payload` |
| Unauthenticated or spoofed actor | `test_api_requires_login_by_default`, `test_acknowledge_uses_session_user_not_body`, `test_dismiss_validates_reason_and_records_session_actor` |
| Alert spam | `test_dms_are_not_resent`, `test_escalation_posts_once_per_stage`, `test_end_to_end_scan_is_idempotent` |
| Weekend escalation for routine findings | `test_escalation_waits_for_posting_window`, `test_friday_plus_one_working_day_is_monday_same_time` |
| Duplicate PR next to Renovate/Dependabot | `test_reuses_bot_pr_and_upserts_single_comment` |
