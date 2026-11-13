# Renovate Pilot (`ack-desk` via GitHub Actions) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run self-hosted Renovate nightly (`Mo–Do`) from `westcoder/westcode-patchbot` via GitHub Actions against `westcoder/ack-desk` (`develop`), bundling non-major updates with safe automerge while keeping Patchbot v2 bot-PR recognition aligned.

**Architecture:** A scheduled GitHub Actions workflow (`.github/workflows/renovate.yml`) mints a short-lived `westcode-renovate` GitHub App token and runs `renovatebot/github-action` against the central runner configuration in `deploy/renovate.json` (`02:00 UTC` creates/updates the grouped PR; `03:00 UTC` merges it once CI checks pass). Patchbot's `research.bot_prs` recognizes `westcode-renovate[bot]`, and the superseded static-token `renovate` container is removed from `deploy/compose.yaml`.

**Tech Stack:** GitHub Actions (`actions/create-github-app-token@v2`, `renovatebot/github-action@v46`), Renovate JSON configuration, Python 3.12 / Django / pytest.

**Spec:** `docs/superpowers/specs/2026-11-11-renovate-pilot-design.md`

## Global Constraints

- Target repository for Phase 1: `{"repository": "westcoder/ack-desk", "baseBranches": ["develop"]}` with `"onboarding": false`, `"requireConfig": "optional"`, `"includeForks": true`, `"semanticCommits": "enabled"`.
- Enabled managers: `["poetry", "pep621", "npm", "dockerfile", "docker-compose", "github-actions", "circleci"]`.
- Non-major updates (`minor`, `patch`, `pin`, `digest`) grouped into `"non-major dependencies"` (`groupSlug: "non-major"`) with `"automerge": true`, `"platformAutomerge": false`, `"ignoreTests": false`.
- `major` updates (`"rebaseWhen": "conflicted"`) and security updates (`osvVulnerabilityAlerts: true`, `vulnerabilityAlerts`) isolated (`"groupName": null`) with `"automerge": false`.
- Schedule strictly `Mo–Do` (`0 2 * * 1-4` and `0 3 * * 1-4` UTC, after `ack-desk`'s `01:00 UTC` `nightly-merge-back`), plus `workflow_dispatch` with safe `dry_run` preview default (`"full"`).
- GitHub App bot login: `"westcode-renovate[bot]"`; AWS CodeArtifact account ID for Phase-2 preparation: `069962555850` (never stale `533267181938`).

## Review Focus

- Grouped PR titles (`chore(deps): update non-major dependencies`) from `westcode-renovate[bot]` must still return `None` in `parse_bot_pr` instead of crashing or creating bogus single-package `MaintenanceUpdate` rows.
- Security patches on `minor`/`patch` versions must not inherit `automerge: true` or grouping from the `non-major` rule (`vulnerabilityAlerts` must explicitly set `groupName: null` and `automerge: false`).
- Cron schedules must exclude Friday–Sunday (`0,5,6`), and `platformAutomerge` must be `false` so merges do not fail when `ack-desk` has no native GitHub auto-merge rule on `develop`.
- Renovate v38+ rejects `RENOVATE_DRY_RUN=false`; `RENOVATE_DRY_RUN` must only be exported when `dry_run` is `"full"` or `"lookup"`, remaining unset on cron runs and `"off"` dispatches.
- Stale AWS account ID `533267181938` must not survive anywhere in `deploy/` or `.github/`, so Phase-2 CodeArtifact activation targets `069962555850`.

---

### Task 1: Recognize `westcode-renovate[bot]` in Patchbot PR Parser

**Files:**
- Modify: `backend/research/bot_prs.py:8-13`
- Test: `backend/research/tests/test_bot_prs.py`

**Interfaces:**
- Consumes: none
- Produces: `BOT_LOGINS: set[str]` containing `{"renovate[bot]", "westcode-renovate[bot]", "dependabot[bot]"}` and unchanged `parse_bot_pr(pr: dict) -> BotPr | None`

- [ ] **Step 1: Add failing parametrized cases to `backend/research/tests/test_bot_prs.py`**

Add `"westcode-renovate[bot]"` single-package cases to `test_parses_renovate_and_dependabot_titles` and a grouped-PR negative assertion to `test_ignores_human_prs_and_group_updates`:

```python
("fix(deps): update dependency django to v6.0.2", "westcode-renovate[bot]", "django", "6.0.2"),
("chore(deps): update dependency @angular/core to v22.2.1", "westcode-renovate[bot]", "@angular/core", "22.2.1"),
```

```python
assert parse_bot_pr(pr("chore(deps): update non-major dependencies", login="westcode-renovate[bot]")) is None
```

- [ ] **Step 2: Run `pytest` to verify the new cases fail**

Run: `cd backend && uv run pytest research/tests/test_bot_prs.py -v`
Expected: FAIL (`parsed` is `None` for `westcode-renovate[bot]`).

- [ ] **Step 3: Add `"westcode-renovate[bot]"` to `BOT_LOGINS` in `backend/research/bot_prs.py`**

Update `BOT_LOGINS` on line 8 to include `"westcode-renovate[bot]"`.

- [ ] **Step 4: Run `pytest` to verify all bot PR tests pass**

Run: `cd backend && uv run pytest research/tests/test_bot_prs.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/research/bot_prs.py backend/research/tests/test_bot_prs.py
git commit -m "feat(research): recognize westcode-renovate[bot] pull requests"
```

---

### Task 2: Central Renovate Pilot Config, Nightly GitHub Action, Compose & Runbook Cleanup

**Files:**
- Create: `.github/workflows/renovate.yml`
- Modify: `deploy/renovate.json`
- Modify: `deploy/compose.yaml:186-206`
- Modify: `deploy/.gitignore`
- Modify: `docs/runbooks/patchbot-v2-rollout.md`
- Test: `backend/fleet/tests/test_deploy_config.py`

**Interfaces:**
- Consumes: GitHub repository secrets `RENOVATE_APP_ID` and `RENOVATE_APP_PRIVATE_KEY`
- Produces: `.github/workflows/renovate.yml` executing `deploy/renovate.json`; `deploy/compose.yaml` without the `renovate` service

- [ ] **Step 1: Replace legacy Renovate assertions and add pilot/workflow tests in `backend/fleet/tests/test_deploy_config.py`**

Update `test_deploy_compose_is_hardened_and_renovate_config_valid()` so `"renovate"` is asserted **absent** from `compose["services"]` and add `test_renovate_pilot_config_and_workflow()` asserting:
- `deploy/renovate.json` has `platform == "github"`, `onboarding is False`, `requireConfig == "optional"`, `includeForks is True`, `semanticCommits == "enabled"`, `osvVulnerabilityAlerts is True`.
- `enabledManagers` contains all 7 managers (`poetry`, `pep621`, `npm`, `dockerfile`, `docker-compose`, `github-actions`, `circleci`).
- `repositories == [{"repository": "westcoder/ack-desk", "baseBranches": ["develop"]}]`.
- `vulnerabilityAlerts` sets `enabled is True`, `groupName is None`, `automerge is False`.
- `packageRules` contains: non-major rule (`automerge is True`, `platformAutomerge is False`, `ignoreTests is False`, `groupSlug == "non-major"`) and major rule (`automerge is False`, `rebaseWhen == "conflicted"`, `groupName is None`).
- `.github/workflows/renovate.yml` parses with `yaml.safe_load`, sets `permissions == {"contents": "read"}`, defines `"on".schedule` crons `["0 2 * * 1-4", "0 3 * * 1-4"]` (every cron's 5th field `== "1-4"`), defines `workflow_dispatch.inputs.dry_run` with `options == ["full", "lookup", "off"]` and `default == "full"`, uses `actions/create-github-app-token@v2` with `owner: westcoder`, sets `RENOVATE_GIT_AUTHOR`, and only exports `RENOVATE_DRY_RUN` when `inputs.dry_run` is `"full"` or `"lookup"` (never `"false"`).
- `"533267181938"` does not appear in `deploy/renovate.json`, `.github/workflows/renovate.yml`, or `docs/runbooks/patchbot-v2-rollout.md`, and `.github/workflows/renovate.yml` documents the Phase-2 CodeArtifact host for account `069962555850`.

- [ ] **Step 2: Run `pytest` to verify the new deployment tests fail**

Run: `cd backend && uv run pytest fleet/tests/test_deploy_config.py -v`
Expected: FAIL (`renovate` still in `compose.yaml`, `.github/workflows/renovate.yml` missing, old `deploy/renovate.json` fields).

- [ ] **Step 3: Update `deploy/renovate.json`, create `.github/workflows/renovate.yml`, and clean up `deploy/compose.yaml`, `deploy/.gitignore`, and `docs/runbooks/patchbot-v2-rollout.md`**

- `deploy/renovate.json`: configure the self-hosted global & package rules pinned in Global Constraints (no unreferenced `{{ secrets.CODEARTIFACT_AUTH_TOKEN }}` in Phase 1).
- `.github/workflows/renovate.yml`: quote `"on":` so YAML 1.1 parsers read key `"on"`, add `concurrency: {group: renovate, cancel-in-progress: false}`, mint token via `actions/create-github-app-token@v2` (`app-id: ${{ secrets.RENOVATE_APP_ID }}`, `private-key: ${{ secrets.RENOVATE_APP_PRIVATE_KEY }}`, `owner: westcoder`), export `RENOVATE_DRY_RUN` into `$GITHUB_ENV` only when `github.event_name == 'workflow_dispatch' && (inputs.dry_run == 'full' || inputs.dry_run == 'lookup')`, invoke `renovatebot/github-action@v46` with `configurationFile: deploy/renovate.json` and `token: ${{ steps.app-token.outputs.token }}` and `RENOVATE_GIT_AUTHOR: "${{ steps.app-token.outputs.app-slug }}[bot] <${{ steps.app-token.outputs.app-slug }}[bot]@users.noreply.github.com>"`, plus a concise commented Phase-2 AWS OIDC step (`069962555850`, `westcode-069962555850.d.codeartifact.eu-central-1.amazonaws.com`, `codeartifact-read-boundary`).
- `deploy/compose.yaml` & `deploy/.gitignore`: remove the `renovate` service block and `renovate.env` entry.
- `docs/runbooks/patchbot-v2-rollout.md`: remove `renovate`/`renovate.env` from the Compose topology & env sections, fix `533267181938` → `069962555850`, and document setting up the `westcode-renovate` GitHub App, secrets (`RENOVATE_APP_ID`, `RENOVATE_APP_PRIVATE_KEY`), `dry_run=full` first run, and adding repositories.

- [ ] **Step 4: Run the full backend test suite to verify everything passes**

Run: `cd backend && uv run pytest -q`
Expected: PASS (all tests green).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/renovate.yml deploy/renovate.json deploy/compose.yaml deploy/.gitignore docs/runbooks/patchbot-v2-rollout.md backend/fleet/tests/test_deploy_config.py
git commit -m "feat(deploy): run Renovate pilot on ack-desk via nightly GitHub Action"
```
