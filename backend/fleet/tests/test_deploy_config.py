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
    for name in ("web", "worker"):
        env = _env_keys(services[name])
        for key in ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_HOST", "POSTGRES_PORT"):
            assert key in env, (name, key)
        assert _env(services[name])["POSTGRES_HOST"] == "postgres"
        # Least privilege: explicit per-service environment instead of the shared .env file.
        assert "env_file" not in services[name], name

    renovate = json.loads((REPO_ROOT / "deploy" / "renovate.json").read_text(encoding="utf-8"))
    for manager in ("poetry", "npm", "dockerfile", "docker-compose", "github-actions", "circleci"):
        assert manager in renovate["enabledManagers"]
    assert "hostRules" in renovate and len(renovate["hostRules"]) >= 1
    assert "packageRules" in renovate and len(renovate["packageRules"]) >= 1


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
