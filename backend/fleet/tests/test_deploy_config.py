import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]


def _compose(name: str = "compose.yaml") -> dict:
    return yaml.safe_load((REPO_ROOT / "deploy" / name).read_text(encoding="utf-8"))


def _env_keys(service: dict) -> list[str]:
    env = service.get("environment", {})
    return list(env) if isinstance(env, dict) else [e.split("=", 1)[0] for e in env]


def _env(service: dict) -> dict:
    env = service.get("environment", {})
    if isinstance(env, dict):
        return {k: ("" if v is None else str(v)) for k, v in env.items()}
    return dict((e.split("=", 1) + [""])[:2] for e in env)


def _volumes(service: dict) -> str:
    return " ".join(v if isinstance(v, str) else f"{v.get('source', '')}:{v.get('target', '')}"
                    for v in service.get("volumes", []))


def test_deploy_compose_is_hardened_and_renovate_config_valid():
    compose = _compose()
    services = compose["services"]

    for name, service in services.items():
        assert service["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in service["security_opt"], name

    assert services["postgres"]["user"] == "postgres"
    assert "renovate" not in services
    for name in ("web", "worker"):
        env = _env_keys(services[name])
        for key in ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_HOST", "POSTGRES_PORT"):
            assert key in env, (name, key)
        assert _env(services[name])["POSTGRES_HOST"] == "postgres"
        # Least privilege: explicit per-service environment instead of the shared .env file.
        assert "env_file" not in services[name], name


def test_renovate_pilot_config_and_workflow():
    renovate_path = REPO_ROOT / "deploy" / "renovate.json"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "renovate.yml"
    runbook_path = REPO_ROOT / "docs" / "runbooks" / "patchbot-v2-rollout.md"

    renovate_text = renovate_path.read_text(encoding="utf-8")
    renovate = json.loads(renovate_text)
    assert renovate["$schema"] == "https://docs.renovatebot.com/renovate-global-schema.json"
    assert renovate["platform"] == "github"
    assert renovate["onboarding"] is False
    assert renovate["requireConfig"] == "optional"
    assert renovate["forkProcessing"] == "enabled"
    assert "includeForks" not in renovate
    assert renovate["globalExtends"] == ["config:recommended"]
    assert "extends" not in renovate
    assert renovate["semanticCommits"] == "enabled"
    assert renovate["dependencyDashboard"] == {"enabled": True}
    assert renovate["osvVulnerabilityAlerts"] is True
    assert renovate["constraints"] == {"npm": "^11.0.0"}
    assert "allow-remote=all" in renovate["npmrc"]
    assert renovate["npmrcMerge"] is True
    for manager in ("poetry", "pep621", "npm", "dockerfile", "docker-compose", "github-actions", "circleci"):
        assert manager in renovate["enabledManagers"], manager
    assert renovate["repositories"] == [
        {"repository": "westcoder/ack-desk", "baseBranchPatterns": ["develop"]},
        {"repository": "westcoder/westcode-hub", "baseBranchPatterns": ["main"]},
        {"repository": "westcoder/projectory", "baseBranchPatterns": ["develop"]},
    ]

    vuln_alerts = renovate["vulnerabilityAlerts"]
    assert vuln_alerts["enabled"] is True
    assert vuln_alerts["groupName"] is None
    assert vuln_alerts["automerge"] is False

    non_major = next(r for r in renovate["packageRules"] if r.get("groupSlug") == "non-major")
    assert set(non_major["matchUpdateTypes"]) >= {"minor", "patch", "pin", "digest"}
    assert non_major["automerge"] is True
    assert non_major["platformAutomerge"] is False
    assert non_major["ignoreTests"] is False
    assert non_major["prPriority"] > 0
    assert non_major["prConcurrentLimit"] >= 10

    major = next(r for r in renovate["packageRules"] if r.get("matchUpdateTypes") == ["major"])
    assert "groupName" not in major
    assert major["automerge"] is False
    assert major["rebaseWhen"] == "conflicted"
    assert major["prConcurrentLimit"] == 2
    assert major["branchConcurrentLimit"] == 2
    # Renovate's HourlyPRs counter is shared with renovate/non-major (prPriority 10),
    # so 2 allows 1 non-major PR + 1 major PR in the same 02:00 UTC run without starving majors.
    assert major["prHourlyLimit"] == 2
    assert major["prPriority"] < 0

    non_major_idx = renovate["packageRules"].index(non_major)
    python_minor = next(
        r
        for r in renovate["packageRules"]
        if r.get("matchPackageNames") == ["python", "cimg/python"] and r.get("matchUpdateTypes") == ["minor"]
    )
    assert renovate["packageRules"].index(python_minor) > non_major_idx
    assert python_minor["groupName"] is None
    assert python_minor["groupSlug"] is None
    assert python_minor["automerge"] is False
    assert python_minor["rebaseWhen"] == "conflicted"
    assert python_minor["prConcurrentLimit"] == 2
    assert python_minor["branchConcurrentLimit"] == 2
    assert python_minor["prHourlyLimit"] == 2
    assert python_minor["prPriority"] < 0

    assert workflow_path.is_file()
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    assert workflow["permissions"] == {"contents": "read", "id-token": "write"}

    crons = [entry["cron"] for entry in workflow["on"]["schedule"]]
    assert crons == ["0 2 * * 1-4", "0 3 * * 1-4"]
    assert all(c.split()[4] == "1-4" for c in crons)

    dry_run_input = workflow["on"]["workflow_dispatch"]["inputs"]["dry_run"]
    assert dry_run_input["options"] == ["full", "lookup", "off"]
    assert dry_run_input["default"] == "full"

    steps = workflow["jobs"]["renovate"]["steps"]
    checkout_step = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout_step["uses"] == "actions/checkout@v6"

    token_step = next(s for s in steps if str(s.get("uses", "")).startswith("actions/create-github-app-token@v3"))
    assert token_step["with"]["owner"] == "westcoder"
    assert "RENOVATE_APP_ID" in token_step["with"]["client-id"]
    assert "RENOVATE_APP_PRIVATE_KEY" in token_step["with"]["private-key"]

    dry_run_step = next(s for s in steps if "RENOVATE_DRY_RUN" in str(s.get("run", "")))
    assert "RENOVATE_DRY_RUN=false" not in dry_run_step["run"]
    assert "${{" not in dry_run_step["run"]
    dry_run_expr = dry_run_step["env"]["DRY_RUN_MODE"]
    assert "github.event_name == 'workflow_dispatch'" in dry_run_expr
    assert "inputs.dry_run == 'full'" in dry_run_expr
    assert "inputs.dry_run == 'lookup'" in dry_run_expr
    assert "%5Bbot%5D" in dry_run_step["run"]
    assert "@users.noreply.github.com" in dry_run_step["run"]

    oidc_step = next(s for s in steps if "RENOVATE_HOST_RULES" in str(s.get("run", "")))
    assert oidc_step["env"]["ROLE_ARN"] == "arn:aws:iam::069962555850:role/westcode-infra/github-renovate-codeartifact-read"
    assert oidc_step["env"]["AWS_DEFAULT_REGION"] == "eu-central-1"
    assert "assume-role-with-web-identity" in oidc_step["run"]
    assert "aws codeartifact get-authorization-token" in oidc_step["run"]
    assert "::add-mask::" in oidc_step["run"]
    assert "westcode-069962555850.d.codeartifact.eu-central-1.amazonaws.com" in oidc_step["run"]
    assert "${{" not in oidc_step["run"]

    renovate_step = next(s for s in steps if str(s.get("uses", "")).startswith("renovatebot/github-action@"))
    assert re.fullmatch(r"renovatebot/github-action@v\d+\.\d+\.\d+", renovate_step["uses"])
    assert renovate_step["with"]["configurationFile"] == "deploy/renovate.json"
    assert "RENOVATE_GIT_AUTHOR" in renovate_step["env"]
    assert "RENOVATE_USERNAME" in renovate_step["env"]

    for path in (renovate_path, workflow_path, runbook_path):
        assert "533267181938" not in path.read_text(encoding="utf-8"), path.name
    assert "westcode-069962555850.d.codeartifact.eu-central-1.amazonaws.com" in workflow_text
    assert "Workflows: **Read and write**" in runbook_path.read_text(encoding="utf-8")


def test_compose_has_web_worker_and_isolated_sandbox_network():
    compose = _compose()
    services = compose["services"]
    assert {"web", "worker", "postgres"} <= set(services)
    assert compose["networks"]["patchbot-sandbox-egress"]["internal"] is True
    for name in ("web", "postgres"):
        assert "/var/run/docker.sock" not in _volumes(services[name])
    assert "SLACK_APP_TOKEN" not in _env_keys(services["worker"])
    assert "SLACK_SIGNING_SECRET" in _env_keys(services["web"])
    assert "GITHUB_WEBHOOK_SECRET" in _env_keys(services["web"])


def test_sandbox_network_has_a_fixed_name_and_only_the_egress_proxy():
    compose = _compose()
    # research.sandbox starts containers with --network=patchbot-sandbox-egress; without an explicit
    # name compose would prefix it with the project name.
    assert compose["networks"]["patchbot-sandbox-egress"]["name"] == "patchbot-sandbox-egress"
    attached = [n for n, s in compose["services"].items() if "patchbot-sandbox-egress" in (s.get("networks") or [])]
    assert attached == ["egress-proxy"]


def test_postgres_is_only_on_an_internal_network_and_not_published():
    compose = _compose()
    postgres = compose["services"]["postgres"]
    assert "ports" not in postgres
    for network in postgres["networks"]:
        assert compose["networks"][network]["internal"] is True


def test_web_is_production_configured_and_only_bound_to_localhost():
    web = _compose()["services"]["web"]
    env = _env(web)
    assert env["DJANGO_DEBUG"] == "false"
    for key in ("DJANGO_SECRET_KEY", "DJANGO_ALLOWED_HOSTS", "DJANGO_CSRF_TRUSTED_ORIGINS", "MICROSOFT_TENANT_ID",
                "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "MICROSOFT_REDIRECT_URI", "SLACK_BOT_TOKEN"):
        assert key in env, key
    assert "PATCHBOT_DEV_LOGIN" not in env
    # The web tier never needs the GitHub App key, Claude or Notion credentials.
    for key in ("ANTHROPIC_API_KEY", "GITHUB_APP_PRIVATE_KEY_PATH", "NOTION_API_KEY"):
        assert key not in env, key
    assert all(str(p).startswith("127.0.0.1:") for p in web["ports"])
    assert "/api/health/" in json.dumps(web["healthcheck"]["test"])


def test_no_service_uses_slack_socket_mode():
    for name in ("compose.yaml", "compose.ai-patching.yaml"):
        text = (REPO_ROOT / "deploy" / name).read_text(encoding="utf-8")
        assert "SLACK_APP_TOKEN" not in text, name


def test_worker_has_repo_cache_and_docker_socket_only_in_ai_patching_override():
    compose = _compose()
    worker = compose["services"]["worker"]
    env = _env(worker)
    assert "run_worker" in " ".join(worker["command"])
    assert "/var/run/docker.sock" not in _volumes(worker)
    assert env["PATCHBOT_AI_PATCHING"] == "false"
    # Host path == container path, so `docker run --volume <worktree>:/work` resolves on the host.
    cache = env["PATCHBOT_REPO_CACHE"]
    assert f"repo-cache:{cache}" in _volumes(worker)
    assert compose["volumes"]["repo-cache"]["driver_opts"]["device"] == cache

    override = _compose("compose.ai-patching.yaml")["services"]["worker"]
    assert "/var/run/docker.sock:/var/run/docker.sock" in _volumes(override)
    assert _env(override)["PATCHBOT_AI_PATCHING"] == "true"
    assert set(_compose("compose.ai-patching.yaml")["services"]) == {"worker"}


def test_sandbox_images_are_non_root_and_carry_no_credentials():
    for name in ("Dockerfile.node22", "Dockerfile.python312"):
        text = (REPO_ROOT / "deploy" / "sandbox" / name).read_text(encoding="utf-8")
        users = re.findall(r"^USER\s+(\S+)", text, flags=re.MULTILINE)
        assert users and users[-1] == "1000:1000", name
        for line in text.splitlines():
            if line.strip().upper().startswith(("ENV ", "ARG ")):
                assert not re.search(r"TOKEN|SECRET|PASSWORD|API_KEY|AUTH", line, re.IGNORECASE), line


def test_rollout_runbook_documents_public_webhook_allowlist():
    text = (REPO_ROOT / "docs" / "runbooks" / "patchbot-v2-rollout.md").read_text(encoding="utf-8")
    assert "/api/webhooks/slack/interactions/" in text
    assert "/api/webhooks/github/" in text
    assert "client_max_body_size 1m" in text
    # Slack runs over HTTP interactivity only (D-1), never Socket Mode.
    assert "socket_mode_enabled: false" in text


def test_deploy_systemd_unit_and_installer_script_are_hardened():
    unit_text = (REPO_ROOT / "deploy" / "westcode-patchbot-agent.service").read_text(encoding="utf-8")
    installer_text = (REPO_ROOT / "deploy" / "install-agent.sh").read_text(encoding="utf-8")

    assert "/usr/local/libexec/westcode-patchbot-agent" in unit_text
    assert "EnvironmentFile=/etc/westcode-patchbot/agent.env" in unit_text

    assert "set -euo pipefail" in installer_text
    assert "/usr/local/libexec/westcode-patchbot-agent" in installer_text
    assert "/etc/westcode-patchbot/agent.env" in installer_text
    assert "chmod 0600" in installer_text
    assert "PATCHBOT_URL" in installer_text
    assert "PATCHBOT_TOKEN" in installer_text
    assert "PATCHBOT_HOSTNAME" in installer_text


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
    # A oneshot unit is triggered by the timer, never enabled on its own.
    assert "[Install]" not in text


def test_installer_enables_timer_not_service():
    text = (REPO_ROOT / "deploy/install-agent.sh").read_text()
    assert "westcode-patchbot-agent.timer" in text
    assert "systemctl enable --now westcode-patchbot-agent.timer" in text
    assert "enable --now westcode-patchbot-agent.service" not in text


def _fenced_blocks(text: str, lang: str) -> list[str]:
    return re.findall(rf"```{lang}\n(.*?)```", text, flags=re.DOTALL)


def test_runbook_proxy_separates_agent_allowlist_from_ui_and_api():
    # Spec §3.3: UI/API only for office/VPN; the VMs may only reach POST /api/agent/report/.
    text = (REPO_ROOT / "docs" / "runbooks" / "patchbot-v2-rollout.md").read_text(encoding="utf-8")
    nginx = "\n".join(_fenced_blocks(text, "nginx"))
    agent_location = re.search(r"location = /api/agent/report/ \{(.*?)\n    \}", nginx, flags=re.DOTALL)
    assert agent_location, "nginx needs an exact location for the agent endpoint"
    assert "patchbot-agents.conf" in agent_location.group(1)
    assert "limit_except POST" in agent_location.group(1)
    for location in ("location /api/ {", "location / {"):
        block = nginx.split(location, 1)[1].split("}", 1)[0]
        assert "patchbot-internal.conf" in block and "patchbot-agents.conf" not in block, location
    internal = nginx.split("# /etc/nginx/snippets/patchbot-internal.conf", 1)[1].split("deny all;", 1)[0]
    assert "Agent-VM" not in internal and "agent/report" not in internal

    caddy = "\n".join(_fenced_blocks(text, "caddyfile"))
    agent_matcher = re.search(r"@agent \{(.*?)\}", caddy, flags=re.DOTALL)
    assert agent_matcher
    assert "path /api/agent/report/" in agent_matcher.group(1)
    assert "method POST" in agent_matcher.group(1)
    assert "remote_ip" in agent_matcher.group(1)
    internal_line = next(line for line in caddy.splitlines() if line.strip().startswith("@internal"))
    assert "Agent" not in internal_line


def test_runbook_builds_the_frontend_that_the_proxy_serves():
    text = (REPO_ROOT / "docs" / "runbooks" / "patchbot-v2-rollout.md").read_text(encoding="utf-8")
    angular = json.loads((REPO_ROOT / "frontend" / "angular.json").read_text(encoding="utf-8"))
    project = next(iter(angular["projects"]))
    output = angular["projects"][project]["architect"]["build"]["options"].get("outputPath", f"dist/{project}")
    served = f"/opt/patchbot/frontend/{output}/browser"
    assert text.count(served) >= 2  # nginx + Caddy
    assert "ng build" in text.split("## 3.", 1)[0]  # server preparation (section 2)
    assert "ng build" in text.split("## 10.", 1)[1].split("## 11.", 1)[0]  # update/migration (section 10)


def test_requests_behind_the_tls_proxy_are_secure():
    from django.test import RequestFactory

    # gunicorn (--forwarded-allow-ips) already maps X-Forwarded-Proto to wsgi.url_scheme; Django trusts the
    # header as well so is_secure()/build_absolute_uri() do not depend on that gunicorn flag.
    command = " ".join(_compose()["services"]["web"]["command"])
    assert "--forwarded-allow-ips" in command
    request = RequestFactory().get("/api/health/", HTTP_X_FORWARDED_PROTO="https")
    assert request.is_secure()
    assert request.build_absolute_uri("/api/auth/entra/callback/").startswith("https://")
    # The proxy must overwrite (not pass through) the header for this to be trustworthy.
    runbook = (REPO_ROOT / "docs" / "runbooks" / "patchbot-v2-rollout.md").read_text(encoding="utf-8")
    assert "proxy_set_header X-Forwarded-Proto https;" in runbook


def test_installer_stops_v1_daemon_before_replacing_files_and_enabling_timer():
    # v1 ran the agent as a long-lived `Type=simple` + `Restart=always` service. A plain `disable` leaves that
    # process running (and the unit active), so the v2 timer would never fire on upgraded hosts.
    text = (REPO_ROOT / "deploy/install-agent.sh").read_text()
    lines = [line.strip() for line in text.splitlines()]
    stop = next(i for i, line in enumerate(lines)
                if line.startswith("systemctl disable --now westcode-patchbot-agent.service"))
    install_bin = next(i for i, line in enumerate(lines) if line.startswith('install -m 0755 "${AGENT_SRC}"'))
    install_unit = next(i for i, line in enumerate(lines) if line.startswith('install -m 0644 "${SERVICE_SRC}"'))
    enable_timer = lines.index("systemctl enable --now westcode-patchbot-agent.timer")
    assert stop < install_bin < install_unit < enable_timer
    # A bare `disable` without --now must not be the only shutdown path.
    assert "systemctl disable westcode-patchbot-agent.service" not in text


def test_worker_waits_for_a_downloaded_trivy_db():
    services = _compose()["services"]
    check = services["trivy-db"]["healthcheck"]["test"]
    assert check[-1] == "/home/patchbot/.cache/trivy/db/metadata.json"
    assert services["worker"]["depends_on"]["trivy-db"] == {"condition": "service_healthy"}
