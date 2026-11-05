# Westcode Patchbot v2 — Security & Update Triage Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-step. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Westcode Patchbot v2 as a strictly read-only Security & Update Triage Control Plane that links active Notion projects to GitHub repositories, containers, and hosts; uses Claude (`claude-sonnet-4-6`) to filter CVE noise, classify fixes into *Einfache Fixes (48h)* vs. *Komplexe Eingriffe (7d)*, reuse or create Fix-PRs / code-patched Draft-PRs; routes tasks to the right developer via Slack DMs with 3-stage Grace Periods; and verifies live container rollouts (`image_created_at > pr_merged_at` / digest / `/opt` Git SHA) before marking any finding resolved.

**Architecture:** A modular Django 5.2 + DRF backend (`fleet`, `inventory`, `research`, `triage`), a Python stdlib read-only host telemetry agent (`agent/patchbot_agent.py`), and an Angular 22 standalone-component frontend (`frontend/`) with Westcode corporate design and Single-Tenant Microsoft Entra ID OAuth2 (`@westcode.de`).

**Tech Stack:** Python 3.12, Django 5.2, Django REST Framework, Anthropic SDK (`claude-sonnet-4-6`), Notion API (`2022-06-28`), GitHub CLI / REST API, Slack Web & Interactivity API, Angular 22 (Signals), pytest, Karma/Jasmine.

---

## Global Constraints

1. **No Outbound SSH & No Live Host Mutation:** Patchbot must never SSH into hosts or execute mutating commands on production servers. The host agent (`agent/patchbot_agent.py`) runs in read-only report mode by default (`ProtectSystem=strict`).
2. **Active Notion Projects Filter (`is_monitored=True`):** Only projects synced as active/maintenance from Notion with `is_monitored=True` are scanned and allowed to trigger Slack DMs.
3. **Zero Alert Fatigue:** Proactive Auto-PRs, Slack DMs, and 24h timers are triggered **exclusively** for reachable security vulnerabilities (CVEs) and EOL/security host items. Routine non-CVE updates go quietly into `MaintenanceUpdate` (*„Wartungs-Updates“*).
4. **Live Verification Required ("Erst wenn er wirklich läuft"):** Merging a GitHub PR moves an application finding to `PR_MERGED_WAITING_LIVE` (24h Stage 3 grace period), never directly to resolved. It becomes `VERIFIED_LIVE` only when all linked `HostContainer` records confirm `image_created_at > pr_merged_at`, matching digest, or matching `/opt/<dir>` `git_head_sha`. Host `apt` / reboot findings transition directly from `IN_PROGRESS` to `VERIFIED_LIVE` when the host agent reports the package updated / `reboot_required=False`.
5. **Single Alert Channel (Slack Bot Only) + Four-Eyes Dismissal:** No Zammad and no email alerts. Dismissing or snoozing requires a mandatory `dismissal_reason`; for `HIGH` and `CRITICAL` CVEs, a transparency note is posted to `SLACK_TEAM_CHANNEL_ID`.
6. **Backward Compatibility:** Existing unit tests in `fleet`, `catalog`, `rollouts`, `alerts`, and `agent` must continue to pass alongside the new v2 test suites.

---

## File Structure & Responsibilities

### Host Agent & Deployment (`agent/`, `deploy/`)
- `agent/patchbot_agent.py`: Add `kernel_version` (`uname -r`), container `image_created_at` (`docker image inspect` `Created`), and `/opt/<dir>` `git_head_sha` (`git rev-parse HEAD`) to `collect_host_inventory()`. Make `main()` strictly read-only (`POST /api/agent/report/` only) unless `--poll-legacy-jobs` is passed.
- `agent/tests/test_agent.py`: Unit tests for `image_created_at`, `git_head_sha`, `kernel_version`, and read-only default CLI execution.
- `deploy/westcode-patchbot-agent.service`: Add `ProtectSystem=strict` and `ReadOnlyPaths=/opt` so the systemd unit enforces read-only host telemetry.

### Backend (`backend/`)
- `backend/fleet/models.py` & `backend/fleet/api.py`: Add `kernel_version`, `project`, `suggested_project` to `Host`; add `image_created_at`, `git_head_sha`, `project`, `repository` to `HostContainer`; parse and persist these fields in `AgentReportView`.
- `backend/inventory/models.py`: Define `TeamMember`, `Project`, and `RepositoryAsset`.
- `backend/inventory/notion_sync.py`: Sync active/maintenance projects from Notion (`NOTION_API_KEY`, `NOTION_PROJECTS_DATABASE_ID`), resolve `@westcode.de` project leads to `TeamMember`, and run auto-matching heuristics (`auto_suggest_unassigned_assets`) linking `RepositoryAsset`, `Host`, and `HostContainer` to projects.
- `backend/inventory/entra_auth.py`: Single-Tenant Microsoft Entra ID OAuth2 + PKCE helper (`MICROSOFT_TENANT_ID`, `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `@westcode.de` domain check) and 1:1 `TeamMember` user binding.
- `backend/ inventory/tests/test_inventory.py`: Tests for `TeamMember`, `Project`, Notion sync filtering, auto-match suggestions, and Entra ID Single-Tenant validation.
- `backend/research/models.py`: Define `TriageFinding` (full lifecycle + Claude analysis + PR metadata + 3-stage grace period fields) and `MaintenanceUpdate` (quiet non-CVE routine updates).
- `backend/research/claude_triage.py`: Candidate clustering (monitored projects only, separating CVEs/EOL from `MaintenanceUpdate`) and Claude `claude-sonnet-4-6` reachability & complexity analyzer (`FILTERED_IRRELEVANT`, `SIMPLE`, `COMPLEX`, German summaries, `affected_files`, `breaking_changes_de`).
- `backend/research/github_pr.py`: Smart PR engine that reuses existing open Dependabot/Renovate PRs (posting a German Claude analysis comment) or creates an isolated `git worktree` Fix-PR (`SIMPLE`) / code-patched Draft-PR (`COMPLEX`).
- `backend/research/tests/test_research.py`: Tests for candidate separation, `FILTERED_IRRELEVANT` suppression, `SIMPLE` vs. `COMPLEX` classification, Dependabot PR reuse + comment, and new Draft-PR creation.
- `backend/triage/ownership.py`: Ownership cascade (`INFRASTRUCTURE` → default infra owner; `APPLICATION` → most recent human Git commit author on `affected_files` skipping bots, fallback to `project.owner`).
- `backend/triage/lifecycle.py`: 3-stage state machine (`NEW` 24h → `IN_PROGRESS` 48h/7d → `PR_MERGED_WAITING_LIVE` 24h → `VERIFIED_LIVE`), live container verification (`image_created_at > pr_merged_at` / digest / `git_head_sha`), direct `apt`/reboot verification, dismissal/snooze with mandatory reason, and grace-period escalation evaluator.
- `backend/triage/slack_bot.py`: Slack `users.lookupByEmail`, personal DM sender with Block Kit buttons, Team channel escalation & Four-Eyes dismissal notice, and Slack interaction webhook handler.
- `backend/triage/api.py`: Control Plane v2 REST endpoints (`/api/dashboard/`, `/api/findings/<id>/...`, `/api/maintenance/<id>/prepare-pr/`, `/api/projects/...`, `/api/team/...`, `/api/auth/...`, `/api/scans/run/`, `/api/slack/interactions/`).
- `backend/triage/seed_v2.py`: Idempotent v2 seed & live fleet sync orchestrator (`run_daily_scan_and_sync`) so local dev and tests have realistic Westcode projects (Würth, SES Sandmann, Kugler, Lingel, Westcode Service, Infrastruktur), team members, findings across all 3 buckets, unmapped asset suggestions, and maintenance updates.
- `backend/triage/tests/test_triage_and_api.py`: End-to-end unit and API tests for ownership, 3-stage grace periods, `:main` container verification via `image_created_at`, dismissal four-eyes Slack notice, and `/api/dashboard/` Ampel calculation.

### Frontend (`frontend/src/app/`)
- `frontend/src/app/core/patchbot-api.ts`: Add v2 TypeScript interfaces and API methods while preserving existing methods for backward compatibility.
- `frontend/src/app/pages/services-page.ts`: Upgrade to the v2 **Triage-Dashboard** (`/`) with Global Status-Ampel (Rot/Gelb/Grün), mode switcher (*Sicherheits-Triage* vs. *Wartungs-Updates*), grouping toggle (*Nach Aufwand* vs. *Nach Projekt gruppiert* vs. *Nur meine Aufgaben*), 3 triage buckets (*Einfache Fixes 48h*, *Komplexe Eingriffe 7d*, *Gemergt – Wartet auf Live-Gang 24h*), and sticky right-hand Triage Detail Panel with Claude analysis, Grace-Period countdown, *„Ich bin dran“*, *„Snooze / Nicht betroffen“* modal with mandatory reason, PR badge, and live host container verification table.
- `frontend/src/app/pages/projects-page.ts`: Upgrade to **Projekte & Zuordnung** (`/projects`) with Notion Sync button, `is_monitored` toggle, *„Unzugeordnete Assets“-Inbox* with 1-click auto-match confirmation, and `Project ↔ Repo ↔ Container ↔ Host` assignment editor.
- `frontend/src/app/pages/hosts-page.ts`: Upgrade **Live-Hosts** (`/hosts`) to display `kernel_version`, container `image_created_at`, `repo_digests`, and `/opt` `git_head_sha`.
- `frontend/src/app/pages/team-page.ts`: Create **Team & Schichten** (`/team`) page for managing `TeamMember` records (`@westcode.de` email, GitHub username, Slack user ID lookup, layer checkboxes, test DM).
- `frontend/src/app/app.routes.ts` & `frontend/src/app/app.ts`: Update top navigation bar (`Triage-Dashboard`, `Projekte & Zuordnung`, `Live-Hosts`, `Team & Schichten`), Entra ID user badge, and *„Scan & Sync starten“* trigger.

---

### Task 1: Read-Only Host Telemetry Agent v2 & Hardened Systemd Unit

**Files:**
- Modify: `agent/patchbot_agent.py`
- Modify: `agent/tests/test_agent.py`
- Modify: `deploy/westcode-patchbot-agent.service`
- Modify: `backend/fleet/models.py`
- Create: `backend/fleet/migrations/0002_host_v2_telemetry_fields.py`
- Modify: `backend/fleet/api.py`
- Modify: `backend/fleet/tests/test_agent_api.py`

**Interfaces:**
- **Produces:**
  - `collect_host_inventory()` payload keys: `kernel_version: str`, `containers[].image_created_at: str`, `containers[].git_head_sha: str`
  - `Host.kernel_version: CharField`
  - `HostContainer.image_created_at: DateTimeField(null=True)`
  - `HostContainer.git_head_sha: CharField`

- [ ] **Step 1: Write failing tests for v2 telemetry in `agent/tests/test_agent.py` and `backend/fleet/tests/test_agent_api.py`**

Add tests in `agent/tests/test_agent.py` verifying that:
1. `collect_host_inventory()` captures `kernel_version` (from `uname -r`), `image_created_at` (from `docker image inspect` `Created`), and `git_head_sha` (from `git rev-parse HEAD` in `working_dir`).
2. `main()` in default mode only calls `POST /api/agent/report/` and does **not** poll `/api/agent/jobs/next/` unless `--poll-legacy-jobs` is passed.
Add a test in `backend/fleet/tests/test_agent_api.py` verifying that `POST /api/agent/report/` stores `kernel_version` on `Host` and `image_created_at` (parsed ISO datetime) + `git_head_sha` on `HostContainer`.

- [ ] **Step 2: Run pytest to verify the new tests fail**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/pytest ../agent/tests/test_agent.py fleet/tests/test_agent_api.py -v`
Expected: FAIL (`kernel_version`, `image_created_at`, `git_head_sha` missing).

- [ ] **Step 3: Implement read-only telemetry extensions in `agent/patchbot_agent.py`, `deploy/westcode-patchbot-agent.service`, and `backend/fleet/`**

1. In `agent/patchbot_agent.py`:
   - Run `["uname", "-r"]` inside `collect_host_inventory()` to populate `"kernel_version"`.
   - From `docker image inspect <image_id>`, extract `img_data[0].get("Created", "")` into `"image_created_at"`.
   - When `working_dir` is present, run `["git", "rev-parse", "HEAD"]` with `cwd=working_dir` to populate `"git_head_sha"`.
   - In `main()`, add `--poll-legacy-jobs` (`action="store_true"`, default `False`) and only poll `/api/agent/jobs/next/` when `args.poll_legacy_jobs` is True.
2. In `deploy/westcode-patchbot-agent.service`:
   - Add `ProtectSystem=strict` under `[Service]`.
3. In `backend/fleet/models.py` & `backend/fleet/api.py`:
   - Add `kernel_version = models.CharField(max_length=128, blank=True, default="")` to `Host`.
   - Add `image_created_at = models.DateTimeField(null=True, blank=True, default=None)` and `git_head_sha = models.CharField(max_length=128, blank=True, default="")` to `HostContainer`.
   - Parse `image_created_at` with `django.utils.dateparse.parse_datetime` in `AgentReportView.post` and save `kernel_version`, `image_created_at`, and `git_head_sha`.

- [ ] **Step 4: Run pytest to verify all agent and fleet tests pass**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/pytest ../agent/tests/test_agent.py fleet/tests/ -v`
Expected: PASS.

- [ ] **Step 5: Commit Task 1**

Run:
```bash
git add agent/ deploy/westcode-patchbot-agent.service backend/fleet/
git commit -m "feat(agent,fleet): add read-only v2 container build timestamp and git SHA telemetry"
```

---

### Task 2: Inventory Domain, Project-Asset Graph, Notion Sync & Microsoft Entra ID OAuth2

**Files:**
- Create: `backend/inventory/__init__.py`
- Create: `backend/inventory/apps.py`
- Create: `backend/inventory/models.py`
- Create: `backend/inventory/migrations/__init__.py`
- Create: `backend/inventory/migrations/0001_initial.py`
- Modify: `backend/fleet/models.py` (add `project` and `suggested_project` FKs on `Host`; `project` and `repository` FKs on `HostContainer`)
- Create: `backend/fleet/migrations/0003_host_project_links.py`
- Create: `backend/inventory/notion_sync.py`
- Create: `backend/inventory/entra_auth.py`
- Create: `backend/inventory/tests/__init__.py`
- Create: `backend/inventory/tests/test_inventory.py`
- Modify: `backend/config/settings.py`
- Modify: `backend/pyproject.toml`

**Interfaces:**
- **Consumes:** `fleet.models.Host`, `fleet.models.HostContainer`
- **Produces:**
  - `inventory.models.TeamMember(user, name, email, github_username, git_commit_emails, slack_user_id, layers, is_default_infra_owner, is_active)`
  - `inventory.models.Project(slug, name, notion_page_id, notion_status, is_monitored, customer_name, owner, logo_key, last_notion_synced_at)`
  - `inventory.models.RepositoryAsset(full_name, default_branch, project, suggested_project, last_scanned_at, last_commit_sha)`
  - `inventory.notion_sync.sync_notion_projects(notion_pages=None) -> dict`
  - `inventory.notion_sync.auto_suggest_unassigned_assets() -> dict`
  - `inventory.entra_auth.validate_entra_configuration(tenant_id, client_id, allowed_domain)` & `resolve_or_bind_team_member(email, display_name)`

- [ ] **Step 1: Write failing tests in `backend/inventory/tests/test_inventory.py`**

Write tests covering:
1. `sync_notion_projects()` imports Notion pages with status `"Aktiv"` or `"Wartung"` as `Project(is_monitored=True)`, skips/marks archived pages (`"Archiviert"` / `"Abgeschlossen"`) as `is_monitored=False`, and maps the Notion project lead email (`@westcode.de`) to `TeamMember`.
2. `auto_suggest_unassigned_assets()` matches unmapped `RepositoryAsset("westcoder/materialdatenbank")`, `RepositoryAsset("westcoder/wuerth-converter")`, `Host(hostname="mdb.westcode.de")`, and `Host(hostname="converter.westcode.de")` to `Project(slug="wuerth")` as `suggested_project`, and returns them in the unassigned inbox until confirmed.
3. `validate_entra_configuration()` rejects multi-tenant values (`"common"`, `"organizations"`, `"consumers"`) and non-`@westcode.de` emails, and `resolve_or_bind_team_member()` links a `@westcode.de` login 1:1 to `TeamMember`.

- [ ] **Step 2: Run pytest to verify the new tests fail**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/pytest inventory/tests/test_inventory.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'inventory'`).

- [ ] **Step 3: Implement `inventory` models, Notion sync, asset auto-matcher, and Entra ID auth**

1. Add `"inventory"` to `INSTALLED_APPS` in `backend/config/settings.py` and `"inventory/tests"` to `testpaths` in `backend/pyproject.toml`.
2. Implement `TeamMember`, `Project`, and `RepositoryAsset` in `backend/inventory/models.py`, and add `project` / `suggested_project` FKs to `Host` and `project` / `repository` FKs to `HostContainer` in `backend/fleet/models.py`.
3. Implement `backend/inventory/notion_sync.py`:
   - Queries Notion database (`POST https://api.notion.com/v1/databases/{db_id}/query` when `NOTION_API_KEY` and `NOTION_PROJECTS_DATABASE_ID` are set, or accepts injected `notion_pages` / Westcode project catalog fallback).
   - Filters active statuses (`Aktiv`, `Active`, `In Betrieb`, `Wartung`, `Maintenance`) vs. archived statuses.
   - Implements `auto_suggest_unassigned_assets()` using stack names, hostname prefixes, ECR image repository names, and known Westcode multi-repo mappings (e.g., `materialdatenbank` + `wuerth-converter` → `wuerth`).
4. Implement `backend/inventory/entra_auth.py`:
   - Enforces Single-Tenant Microsoft Entra ID (`MICROSOFT_TENANT_ID` must be a valid tenant UUID/domain, never `common`/`organizations`/`consumers`), PKCE (`S256`) authorization URL builder, token exchange helper, `@westcode.de` domain check, and `resolve_or_bind_team_member()`.

- [ ] **Step 4: Run migrations and pytest to verify `inventory` tests pass**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/python manage.py makemigrations inventory fleet && .venv/bin/pytest inventory/tests/test_inventory.py fleet/tests/ -v`
Expected: PASS.

- [ ] **Step 5: Commit Task 2**

Run:
```bash
git add backend/inventory/ backend/fleet/ backend/config/settings.py backend/pyproject.toml
git commit -m "feat(inventory): add Project asset graph, Notion active-project sync, and Entra ID auth"
```

---

### Task 3: Daily Research Scanner, Claude Triage Engine & Smart GitHub PR / Draft-PR Builder

**Files:**
- Create: `backend/research/__init__.py`
- Create: `backend/research/apps.py`
- Create: `backend/research/models.py`
- Create: `backend/research/migrations/__init__.py`
- Create: `backend/research/migrations/0001_initial.py`
- Create: `backend/research/claude_triage.py`
- Create: `backend/research/github_pr.py`
- Create: `backend/research/tests/__init__.py`
- Create: `backend/research/tests/test_research.py`
- Modify: `backend/config/settings.py`
- Modify: `backend/pyproject.toml`

**Interfaces:**
- **Consumes:** `inventory.models.Project`, `inventory.models.RepositoryAsset`, `fleet.models.Host`, `fleet.models.HostPackage`
- **Produces:**
  - `research.models.TriageFinding` (fields: `project`, `layer`, `repository`, `hosts`, `vulnerability_ids`, `highest_severity`, `package_name`, `current_version`, `target_version`, `complexity`, `reachability_summary_de`, `breaking_changes_de`, `affected_files`, `confidence`, `pr_number`, `pr_url`, `pr_is_draft`, `pr_source`, `ci_status`, `merge_commit_sha`, `assignee`, `assigned_reason_de`, `state`, `discovered_at`, `acknowledged_at`, `pr_merged_at`, `verified_live_at`, `grace_period_ends_at`, `escalation_stage`, `dismissal_reason`, `dismissed_by`, `snoozed_until`, `manual_runbook`)
  - `research.models.MaintenanceUpdate` (fields: `project`, `repository`, `package_name`, `current_version`, `target_version`, `update_type`, `pr_number`, `pr_url`, `ci_status`, `summary_de`, `updated_at`)
  - `research.claude_triage.collect_monitored_candidates() -> dict`
  - `research.claude_triage.analyze_candidate_with_claude(candidate, repo_context=None, llm_client=None) -> dict`
  - `research.github_pr.ensure_or_enrich_github_pr(finding, existing_prs=None, runner=None) -> dict`

- [ ] **Step 1: Write failing tests in `backend/research/tests/test_research.py`**

Write tests verifying:
1. **Active Project Gate & Routine Update Separation:** `collect_monitored_candidates()` ignores projects with `is_monitored=False`, routes CVE/EOL/security-apt items into security candidates, and routes non-CVE dependency updates into `MaintenanceUpdate` without creating a `TriageFinding`.
2. **Claude Reachability Filtering (`FILTERED_IRRELEVANT`):** When Claude determines a CVE is in a dev/test-only dependency or unreachable code path (`is_relevant=False`), the finding is stored with `state="FILTERED_IRRELEVANT"` and `complexity="FILTERED_IRRELEVANT"` and never triggers PR creation or Slack alerts.
3. **Claude `SIMPLE` vs. `COMPLEX` Classification:** Reachable patch/minor updates without breaking call-site changes become `SIMPLE` (48h); updates with breaking API changes in `affected_files` become `COMPLEX` (7d) with populated `breaking_changes_de` and `affected_files`.
4. **Smart Dependabot/Renovate PR Reuse vs. New Draft-PR:**
   - When an open Dependabot/Renovate PR already matches `(repository, package_name)`, `ensure_or_enrich_github_pr()` reuses `pr_number`/`pr_url` (`pr_source="EXISTING_DEPENDABOT_OR_RENOVATE"`) and posts Claude's German triage analysis as a comment on that PR instead of opening a duplicate PR.
   - When no PR exists and `complexity == "COMPLEX"`, `ensure_or_enrich_github_pr()` creates a Draft-PR (`pr_is_draft=True`, `pr_source="PATCHBOT_CLAUDE_DRAFT"`) including Claude's code patches on `affected_files`.

- [ ] **Step 2: Run pytest to verify the new tests fail**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/pytest research/tests/test_research.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'research'`).

- [ ] **Step 3: Implement `research` models, Claude triage engine, and smart GitHub PR builder**

1. Add `"research"` to `INSTALLED_APPS` in `backend/config/settings.py` and `"research/tests"` to `testpaths` in `backend/pyproject.toml`.
2. Create `TriageFinding` and `MaintenanceUpdate` in `backend/research/models.py`.
3. Create `backend/research/claude_triage.py`:
   - `collect_monitored_candidates()` queries only `Project.objects.filter(is_monitored=True)`.
   - `analyze_candidate_with_claude()` calls Anthropic's Messages API (`model=os.environ.get("PATCHBOT_CLAUDE_MODEL", "claude-sonnet-4-6")`) when `ANTHROPIC_API_KEY` or `llm_client` is provided, and provides a deterministic structured analyzer when running offline/in tests.
4. Create `backend/research/github_pr.py`:
   - `ensure_or_enrich_github_pr()` checks open Dependabot/Renovate PRs first; if found, links the PR and posts a structured German comment (`gh pr comment`).
   - Otherwise, prepares a Fix-PR (`SIMPLE`) or a Claude code-patched Draft-PR (`COMPLEX`) in an isolated worktree.

- [ ] **Step 4: Run migrations and pytest to verify `research` tests pass**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/python manage.py makemigrations research && .venv/bin/pytest research/tests/test_research.py -v`
Expected: PASS.

- [ ] **Step 5: Commit Task 3**

Run:
```bash
git add backend/research/ backend/config/settings.py backend/pyproject.toml
git commit -m "feat(research): add Claude reachability triage, MaintenanceUpdate split, and smart PR reuse/Draft-PR engine"
```

---

### Task 4: Triage Lifecycle, Ownership Cascade, 3-Stage Grace Periods, Live Verification & Slack Bot

**Files:**
- Create: `backend/triage/__init__.py`
- Create: `backend/triage/apps.py`
- Create: `backend/triage/ownership.py`
- Create: `backend/triage/lifecycle.py`
- Create: `backend/triage/slack_bot.py`
- Create: `backend/triage/tests/__init__.py`
- Create: `backend/triage/tests/test_triage_lifecycle.py`
- Modify: `backend/config/settings.py`
- Modify: `backend/pyproject.toml`

**Interfaces:**
- **Consumes:** `inventory.models.TeamMember`, `inventory.models.Project`, `fleet.models.Host`, `fleet.models.HostContainer`, `research.models.TriageFinding`
- **Produces:**
  - `triage.ownership.resolve_finding_assignee(finding, git_log_authors=None) -> tuple[TeamMember | None, str]`
  - `triage.lifecycle.acknowledge_finding(finding, actor: TeamMember | None = None, now=None) -> TriageFinding`
  - `triage.lifecycle.mark_finding_pr_merged(finding, merge_commit_sha: str = "", merged_at=None) -> TriageFinding`
  - `triage.lifecycle.verify_live_rollouts(now=None) -> list[TriageFinding]`
  - `triage.lifecycle.dismiss_or_snooze_finding(finding, actor: TeamMember, mode: str, reason: str, snooze_days: int = 14, slack_sender=None) -> TriageFinding`
  - `triage.lifecycle.evaluate_grace_periods(now=None, slack_sender=None) -> list[TriageFinding]`
  - `triage.slack_bot.SlackBotClient` (DM notification, Team channel escalation, Four-Eyes dismissal notice, interactive button payload handler)

- [ ] **Step 1: Write failing tests in `backend/triage/tests/test_triage_lifecycle.py`**

Write tests verifying:
1. **Ownership Cascade (`resolve_finding_assignee`):**
   - `INFRASTRUCTURE` layer routes to `TeamMember(is_default_infra_owner=True)`.
   - `APPLICATION` layer inspects `git_log_authors`, skips `dependabot[bot]`, `renovate[bot]`, and `github-actions[bot]`, matches the most recent human author by `github_username` or `email` (`@westcode.de`), and falls back to `project.owner` if no Git author matches.
2. **3-Stage Grace Periods & Escalation (`NEW` → `IN_PROGRESS` → `PR_MERGED_WAITING_LIVE` → `VERIFIED_LIVE`):**
   - Creating a finding sets `state="NEW"` and `grace_period_ends_at = discovered_at + 24h`.
   - `acknowledge_finding()` („Ich bin dran“) sets `state="IN_PROGRESS"` and `grace_period_ends_at = +48h` (`SIMPLE`) or `+7d` (`COMPLEX`).
   - `mark_finding_pr_merged()` sets `state="PR_MERGED_WAITING_LIVE"` and `grace_period_ends_at = pr_merged_at + 24h` (never directly `VERIFIED_LIVE`).
   - `evaluate_grace_periods()` increments `escalation_stage` (`1` for expired `NEW`, `2` for expired `IN_PROGRESS`, `3` for expired `PR_MERGED_WAITING_LIVE`) and posts an escalation alert to `SLACK_TEAM_CHANNEL_ID`.
3. **Live Container Verification on `:main` Tags (`verify_live_rollouts`):**
   - When a container on `mdb.westcode.de` has `image_tag="...:main"` and `image_created_at <= pr_merged_at`, the finding stays in `PR_MERGED_WAITING_LIVE`.
   - As soon as `mdb.westcode.de` and `converter.westcode.de` report `image_created_at > pr_merged_at` (or matching `git_head_sha`), `verify_live_rollouts()` transitions the finding to `VERIFIED_LIVE`.
   - For an `INFRASTRUCTURE` `apt` finding (no Git PR), `verify_live_rollouts()` transitions directly from `IN_PROGRESS` to `VERIFIED_LIVE` once the host's security `HostPackage` is gone and `reboot_required=False`.
4. **Dismissal / Snooze & Four-Eyes Slack Transparency:**
   - Calling `dismiss_or_snooze_finding()` with an empty `reason` raises `ValueError`.
   - Calling `dismiss_or_snooze_finding()` on a `CRITICAL` or `HIGH` CVE with `mode="DISMISSED_NOT_EXPLOITABLE"` or `mode="SNOOZED"` transitions the finding and posts a Four-Eyes transparency message to the Team Slack channel.

- [ ] **Step 2: Run pytest to verify the new tests fail**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/pytest triage/tests/test_triage_lifecycle.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'triage'`).

- [ ] **Step 3: Implement `triage/ownership.py`, `triage/lifecycle.py`, and `triage/slack_bot.py`**

1. Add `"triage"` to `INSTALLED_APPS` in `backend/config/settings.py` and `"triage/tests"` to `testpaths` in `backend/pyproject.toml`.
2. Implement `resolve_finding_assignee()` in `backend/triage/ownership.py`.
3. Implement `acknowledge_finding()`, `mark_finding_pr_merged()`, `verify_live_rollouts()`, `dismiss_or_snooze_finding()`, `extend_finding_grace_period()`, and `evaluate_grace_periods()` in `backend/triage/lifecycle.py`.
4. Implement `SlackBotClient` and `handle_slack_interaction_payload()` in `backend/triage/slack_bot.py`.

- [ ] **Step 4: Run pytest to verify all `triage` lifecycle tests pass**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/pytest triage/tests/test_triage_lifecycle.py -v`
Expected: PASS.

- [ ] **Step 5: Commit Task 4**

Run:
```bash
git add backend/triage/ backend/config/settings.py backend/pyproject.toml
git commit -m "feat(triage): add ownership cascade, 3-stage grace periods, live verification, and Slack bot"
```

---

### Task 5: Control Plane v2 REST API & Daily Scan / Seed Orchestrator

**Files:**
- Create: `backend/triage/api.py`
- Create: `backend/triage/seed_v2.py`
- Create: `backend/triage/management/__init__.py`
- Create: `backend/triage/management/commands/__init__.py`
- Create: `backend/triage/management/commands/run_daily_scan.py`
- Create: `backend/triage/tests/test_api_v2.py`
- Modify: `backend/config/urls.py`
- Modify: `backend/rollouts/api.py` (serialize `kernel_version`, `image_created_at`, `git_head_sha`, `repo_digests`, `project` on hosts)

**Interfaces:**
- **Consumes:** `inventory`, `research`, `triage`, `fleet`
- **Produces REST Endpoints:**
  - `GET /api/dashboard/` → `{ status_ampel: { color: "RED"|"YELLOW"|"GREEN", label_de, subline_de, counts }, simple_fixes: [...], complex_fixes: [...], waiting_live: [...], maintenance_updates: [...], projects_summary: [...] }`
  - `POST /api/findings/<int:finding_id>/acknowledge/`
  - `POST /api/findings/<int:finding_id>/dismiss/` (requires `{ mode: "SNOOZED"|"DISMISSED_NOT_EXPLOITABLE", reason: str, snooze_days?: int }`)
  - `POST /api/findings/<int:finding_id>/extend/`
  - `POST /api/findings/<int:finding_id>/prepare-pr/`
  - `POST /api/maintenance/<int:update_id>/prepare-pr/`
  - `GET /api/triage-projects/` & `POST /api/triage-projects/sync-notion/` & `POST /api/triage-projects/<slug:slug>/assign-assets/` & `POST /api/triage-projects/<slug:slug>/toggle-monitoring/`
  - `GET /api/team/` & `POST /api/team/` & `PATCH /api/team/<int:member_id>/` & `POST /api/team/<int:member_id>/test-dm/`
  - `GET /api/auth/me/` & `GET /api/auth/entra/login/` & `GET /api/auth/entra/callback/`
  - `POST /api/slack/interactions/`
  - `POST /api/scans/run/` (and `POST /api/sync/` also triggers `run_daily_scan_and_sync()` so the header button updates both v1 and v2 views)

- [ ] **Step 1: Write failing API tests in `backend/triage/tests/test_api_v2.py`**

Write tests verifying:
1. `GET /api/dashboard/` computes `status_ampel.color == "RED"` when an unacknowledged `NEW` or escalated finding exists, `"YELLOW"` when all open findings are `IN_PROGRESS` or `PR_MERGED_WAITING_LIVE` within their grace period, and `"GREEN"` when all findings are `VERIFIED_LIVE` / dismissed.
2. `POST /api/findings/<id>/acknowledge/` moves the finding to `IN_PROGRESS` and flips the Ampel from `RED` to `YELLOW`.
3. `POST /api/findings/<id>/dismiss/` returns `400 Bad Request` if `reason` is empty, and succeeds + records `dismissal_reason` when provided.
4. `GET /api/triage-projects/` returns monitored Notion projects alongside `unassigned_assets` (with `suggested_project`), and `POST /api/triage-projects/<slug>/assign-assets/` binds repositories, hosts, and containers to the project.
5. `GET /api/team/` and `POST /api/team/` manage `@westcode.de` team members and layer assignments.

- [ ] **Step 2: Run pytest to verify the new API tests fail**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/pytest triage/tests/test_api_v2.py -v`
Expected: FAIL (`404 Not Found`).

- [ ] **Step 3: Implement `backend/triage/api.py`, `backend/triage/seed_v2.py`, `run_daily_scan` command, and `backend/config/urls.py`**

1. Implement `backend/triage/seed_v2.py` (`run_daily_scan_and_sync()`) which ensures the Westcode team members, Notion projects (Würth bundling `mdb.westcode.de` + `converter.westcode.de` + `westcoder/materialdatenbank` + `westcoder/wuerth-converter`, SES Sandmann, Kugler, Lingel, Westcode Service, Infrastruktur), live container timestamps, realistic `TriageFinding` items (`SIMPLE`, `COMPLEX`, `PR_MERGED_WAITING_LIVE`), `MaintenanceUpdate` items, and unassigned asset suggestions are populated and synced.
2. Implement all v2 API views in `backend/triage/api.py` and register them in `backend/config/urls.py`.
3. Update `serialize_host()` in `backend/rollouts/api.py` to include `kernel_version`, `project_slug`, `project_name`, and on containers `image_created_at`, `git_head_sha`, and `repo_digests`.

- [ ] **Step 4: Run the full backend pytest suite and `manage.py run_daily_scan`**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/backend && .venv/bin/pytest -v && .venv/bin/python manage.py run_daily_scan`
Expected: All backend tests pass and `run_daily_scan` populates the SQLite database cleanly.

- [ ] **Step 5: Commit Task 5**

Run:
```bash
git add backend/triage/ backend/config/urls.py backend/rollouts/api.py
git commit -m "feat(api): expose v2 triage dashboard, project asset inbox, team directory, and daily scan command"
```

---

### Task 6: Angular 22 Control Plane Frontend v2 (`frontend/`)

**Files:**
- Modify: `frontend/src/app/core/patchbot-api.ts`
- Modify: `frontend/src/app/app.routes.ts`
- Modify: `frontend/src/app/app.ts`
- Modify: `frontend/src/app/pages/services-page.ts`
- Modify: `frontend/src/app/pages/services-page.spec.ts`
- Modify: `frontend/src/app/pages/projects-page.ts`
- Modify: `frontend/src/app/pages/hosts-page.ts`
- Create: `frontend/src/app/pages/team-page.ts`

**Interfaces:**
- **Consumes:** `/api/dashboard/`, `/api/findings/<id>/...`, `/api/maintenance/<id>/prepare-pr/`, `/api/triage-projects/...`, `/api/hosts/...`, `/api/team/...`, `/api/auth/me/`, `/api/scans/run/`
- **Produces:**
  - `/` (`ServicesPage` upgraded to v2 **Triage-Dashboard**):
    - Global Status-Ampel banner (`RED` / `YELLOW` / `GREEN`)
    - Sub-switch: **„Sicherheits-Triage (CVEs & EOL)“** vs. **„Wartungs-Updates (ohne CVE)“**
    - Grouping toggle: **„Nach Aufwand (Quick Wins / Komplex)“** vs. **„Nach Projekt gruppiert (Würth, SES, …)“** + **„Nur meine Aufgaben“** filter
    - 3 sections: **1. Einfache Fixes (48h)**, **2. Komplexe Eingriffe (7d)**, **3. Gemergt – Wartet auf Live-Gang (24h)**
    - Sticky Right-Hand Triage Detail Panel with Claude reachability & breaking-change analysis, affected file paths, Grace-Period countdown, **„Ich bin dran“** button, **„Snooze / Nicht betroffen“** modal with mandatory justification input, PR/Draft-PR badge, live container `Image.Created` vs. `pr_merged_at` verification table, and manual terminal runbook
  - `/projects` (`ProjectsPage` upgraded to **Projekte & Zuordnung**):
    - Notion Sync button + `is_monitored` toggle per project
    - **„Unzugeordnete Assets“-Inbox** with 1-click **„Vorschlag übernehmen“** button
    - `Projekt ↔ GitHub-Repos ↔ Container ↔ Hosts` assignment matrix
  - `/hosts` (`HostsPage` upgraded to **Live-Hosts (23)**):
    - Read-only telemetry details (`kernel_version`, container `image_created_at`, `repo_digests`, `/opt` `git_head_sha` + `git_clean`), manual runbooks, and token generator
  - `/team` (`TeamPage` **Team & Schichten**):
    - `@westcode.de` team member table & form (`name`, `email`, `github_username`, `slack_user_id`, `layers`, `is_default_infra_owner`, Slack test DM button)

- [ ] **Step 1: Write failing frontend component tests in `frontend/src/app/pages/services-page.spec.ts`**

Update `frontend/src/app/pages/services-page.spec.ts` to test:
1. Rendering the Global Status-Ampel (`Handlungsbedarf` / `In Bearbeitung` / `Alles im grünen Bereich`) from `/api/dashboard/`.
2. Rendering the 3 triage buckets (*Einfache Fixes*, *Komplexe Eingriffe*, *Gemergt – Wartet auf Live-Gang*) and switching to *Wartungs-Updates (ohne CVE)*.
3. Clicking **„Ich bin dran“** calls `acknowledgeFinding(id)` and updates the finding state to `IN_PROGRESS`.
4. Opening the **„Snooze / Nicht betroffen“** modal requires a non-empty justification before calling `dismissFinding(id, payload)`.

- [ ] **Step 2: Run Angular test suite to verify the new tests fail**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/frontend && npx ng test --watch=false --browsers=ChromeHeadless`
Expected: FAIL.

- [ ] **Step 3: Implement `PatchbotApi` v2 methods, `ServicesPage` (Triage-Dashboard), `ProjectsPage` (Asset Graph & Inbox), `HostsPage` (v2 Telemetry), `TeamPage`, and `App` header**

1. Extend `frontend/src/app/core/patchbot-api.ts` with `DashboardResponseDto`, `TriageFindingDto`, `MaintenanceUpdateDto`, `TriageProjectDto`, `UnassignedAssetsDto`, `TeamMemberDto`, and `AuthUserDto`.
2. Implement the v2 **Triage-Dashboard** in `frontend/src/app/pages/services-page.ts`.
3. Implement the v2 **Projekte & Zuordnung** view (with Notion sync, `is_monitored` toggle, and „Unzugeordnete Assets“-Inbox) in `frontend/src/app/pages/projects-page.ts`.
4. Update `frontend/src/app/pages/hosts-page.ts` to show container `image_created_at`, `repo_digests`, and `/opt` `git_head_sha`.
5. Create `frontend/src/app/pages/team-page.ts` and register `/team` in `frontend/src/app/app.routes.ts` and `frontend/src/app/app.ts`.

- [ ] **Step 4: Run Angular unit tests and production build**

Run: `cd /Users/pietzschke/projects/westcode-patchbot/frontend && npx ng test --watch=false --browsers=ChromeHeadless && npx ng build`
Expected: All Karma/Jasmine specs PASS and production build succeeds with zero errors.

- [ ] **Step 5: Commit Task 6**

Run:
```bash
git add frontend/
git commit -m "feat(frontend): build v2 Triage-Dashboard, Project Asset Inbox, Live-Hosts telemetry, and Team view"
```

---

## Review Focus (Critical Failure Modes & Verification)

1. **Mutable `:main` Tag Premature Resolution:**
   - *Failure mode:* A GitHub PR is merged for `westcoder/materialdatenbank`, and Patchbot marks the CVE resolved even though `mdb.westcode.de` still runs a container built 3 days before the PR merge.
   - *Test:* `test_verify_live_rollouts_requires_post_merge_container_build_timestamp` in `backend/triage/tests/test_triage_lifecycle.py` verifies that `state` stays `PR_MERGED_WAITING_LIVE` while `image_created_at <= pr_merged_at` and only transitions to `VERIFIED_LIVE` once all linked containers report `image_created_at > pr_merged_at`.
2. **Archived Notion Projects Triggering Scans or Slack Alerts:**
   - *Failure mode:* An old customer project archived in Notion or toggled to `is_monitored=False` triggers daily CVE scans and Slack DMs.
   - *Test:* `test_unmonitored_and_archived_notion_projects_excluded_from_scan` in `backend/research/tests/test_research.py` verifies zero findings or alerts are generated for `Project(is_monitored=False)`.
3. **Bot Commits Skewing Git Ownership:**
   - *Failure mode:* `dependabot[bot]` or `renovate[bot]` was the last author on `package.json`, so ownership fails to match the human developer who actually touched the code before the bot.
   - *Test:* `test_ownership_skips_bot_authors_and_matches_human_developer_with_notion_fallback` in `backend/triage/tests/test_triage_lifecycle.py`.
4. **Silent Dismissal of High/Critical CVEs Without Justification:**
   - *Failure mode:* A developer clicks *„Nicht betroffen“* on a `CRITICAL` CVE without a reason or without team visibility.
   - *Test:* `test_dismiss_high_or_critical_cve_requires_reason_and_posts_four_eyes_slack_notice` in `backend/triage/tests/test_triage_lifecycle.py` and `test_dismiss_endpoint_validates_reason` in `backend/triage/tests/test_api_v2.py`.
5. **Duplicate PRs When Dependabot/Renovate Already Opened One:**
   - *Failure mode:* Patchbot opens a second PR for the same package bump that Dependabot already has open.
   - *Test:* `test_reuses_existing_dependabot_pr_and_posts_claude_comment` in `backend/research/tests/test_research.py`.
