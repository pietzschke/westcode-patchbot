#!/usr/bin/env bash
# Richtet das Repository-Ruleset „Patchbot nur auf patchbot/*“ idempotent über die GitHub-API ein.
# Hintergrund: GitHub Organization-Rulesets erfordern GitHub Enterprise Cloud; auf GitHub Team
# greifen stattdessen Repository-Rulesets pro Projekt-Repository (Runbook §6.3).
#
# Ergebnis:
# - Rollen Write (2), Maintain (4), Admin (5) sowie westcode-renovate (App ID 5715770) behalten Bypass.
# - Die GitHub App `westcode-patchbot` steht NICHT auf der Bypass-Liste und kann dadurch trotz
#   `Contents: Read and write` ausschließlich Branches unter `refs/heads/patchbot/**` anlegen/aktualisieren.
#
# Aufruf:
#   PATCHBOT_APP_ID=<app-id-von-westcode-patchbot> ./deploy/setup-patchbot-rulesets.sh [repo1 repo2 ...]
set -euo pipefail

RULESET_NAME="Patchbot nur auf patchbot/*"
RENOVATE_APP_ID=5715770

if [ -z "${PATCHBOT_APP_ID:-}" ]; then
  echo "Fehler: Bitte PATCHBOT_APP_ID=<id> der GitHub App westcode-patchbot angeben (Sicherheitsprüfung gegen Verwechslung)." >&2
  exit 1
fi
if [ "${PATCHBOT_APP_ID}" = "${RENOVATE_APP_ID}" ]; then
  echo "Fehler: PATCHBOT_APP_ID darf nicht der Renovate-App (${RENOVATE_APP_ID}) entsprechen." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$#" -gt 0 ]; then
  REPOS=("$@")
else
  mapfile -t REPOS < <(jq -r '.repositories[].repository | sub("^westcoder/"; "")' "${SCRIPT_DIR}/renovate.json")
fi

PAYLOAD="$(jq -cn --arg name "${RULESET_NAME}" --argjson renovate_id "${RENOVATE_APP_ID}" '{
  name: $name,
  target: "branch",
  enforcement: "active",
  bypass_actors: [
    {actor_id: 2, actor_type: "RepositoryRole", bypass_mode: "always"},
    {actor_id: 4, actor_type: "RepositoryRole", bypass_mode: "always"},
    {actor_id: 5, actor_type: "RepositoryRole", bypass_mode: "always"},
    {actor_id: $renovate_id, actor_type: "Integration", bypass_mode: "always"}
  ],
  conditions: {
    ref_name: {
      include: ["~ALL"],
      exclude: ["refs/heads/patchbot/**"]
    }
  },
  rules: [
    {type: "creation"},
    {type: "update"},
    {type: "deletion"}
  ]
}')"

for REPO in "${REPOS[@]}"; do
  SLUG="${REPO#westcoder/}"
  EXISTING_ID="$(gh api "repos/westcoder/${SLUG}/rulesets" --jq ".[] | select(.name == \"${RULESET_NAME}\") | .id" | head -n 1 || true)"
  if [ -n "${EXISTING_ID}" ]; then
    gh api -X PUT "repos/westcoder/${SLUG}/rulesets/${EXISTING_ID}" --input - <<<"${PAYLOAD}" >/dev/null
    echo "Aktualisiert: westcoder/${SLUG} (Ruleset #${EXISTING_ID})"
  else
    NEW_ID="$(gh api -X POST "repos/westcoder/${SLUG}/rulesets" --input - <<<"${PAYLOAD}" --jq .id)"
    echo "Angelegt:     westcoder/${SLUG} (Ruleset #${NEW_ID})"
  fi
done
