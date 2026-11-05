#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PATCHBOT_URL="${PATCHBOT_URL:-https://patch.westcode.de}"
PATCHBOT_TOKEN="${PATCHBOT_TOKEN:?PATCHBOT_TOKEN environment variable is required}"
PATCHBOT_HOSTNAME="${PATCHBOT_HOSTNAME:-$(hostname -f)}"

AGENT_SRC="${REPO_ROOT}/agent/patchbot_agent.py"
AGENT_BIN="/usr/local/libexec/westcode-patchbot-agent"
CONFIG_DIR="/etc/westcode-patchbot"
ENV_FILE="/etc/westcode-patchbot/agent.env"
SERVICE_SRC="${SCRIPT_DIR}/westcode-patchbot-agent.service"
SERVICE_DST="/etc/systemd/system/westcode-patchbot-agent.service"

install -d -m 0755 /usr/local/libexec
install -m 0755 "${AGENT_SRC}" "${AGENT_BIN}"

install -d -m 0700 "${CONFIG_DIR}"
cat > "${ENV_FILE}" <<EOF
PATCHBOT_URL=${PATCHBOT_URL}
PATCHBOT_TOKEN=${PATCHBOT_TOKEN}
PATCHBOT_HOSTNAME=${PATCHBOT_HOSTNAME}
EOF
chmod 0600 "${ENV_FILE}"

install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"

systemctl daemon-reload
systemctl enable --now westcode-patchbot-agent.service
