import json
from pathlib import Path
import yaml


def test_deploy_compose_is_hardened_and_renovate_config_valid():
    root = Path(__file__).resolve().parents[3]
    compose = yaml.safe_load((root / "deploy" / "compose.yaml").read_text(encoding="utf-8"))

    assert "db" in compose["services"]
    assert "trivy" in compose["services"]
    assert "backend" in compose["services"]
    assert "renovate" in compose["services"]
    assert compose["services"]["backend"]["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in compose["services"]["backend"]["security_opt"]
    assert compose["services"]["trivy"]["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in compose["services"]["trivy"]["security_opt"]
    assert compose["services"]["renovate"]["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in compose["services"]["renovate"]["security_opt"]

    renovate = json.loads((root / "deploy" / "renovate.json").read_text(encoding="utf-8"))
    for manager in ("poetry", "npm", "dockerfile", "docker-compose", "github-actions", "circleci"):
        assert manager in renovate["enabledManagers"]
    assert "hostRules" in renovate and len(renovate["hostRules"]) >= 1
    assert "packageRules" in renovate and len(renovate["packageRules"]) >= 1


def test_deploy_systemd_unit_and_installer_script_are_hardened():
    root = Path(__file__).resolve().parents[3]
    unit_text = (root / "deploy" / "westcode-patchbot-agent.service").read_text(encoding="utf-8")
    installer_text = (root / "deploy" / "install-agent.sh").read_text(encoding="utf-8")

    assert "/usr/local/libexec/westcode-patchbot-agent" in unit_text
    assert "EnvironmentFile=/etc/westcode-patchbot/agent.env" in unit_text

    assert "set -euo pipefail" in installer_text
    assert "/usr/local/libexec/westcode-patchbot-agent" in installer_text
    assert "/etc/westcode-patchbot/agent.env" in installer_text
    assert "chmod 0600" in installer_text
    assert "PATCHBOT_URL" in installer_text
    assert "PATCHBOT_TOKEN" in installer_text
    assert "PATCHBOT_HOSTNAME" in installer_text
