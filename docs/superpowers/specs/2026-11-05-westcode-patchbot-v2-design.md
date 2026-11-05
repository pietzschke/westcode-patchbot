# Westcode Patchbot v2 — Security & Update Triage Control Plane (Design Specification)

**Date:** 2026-11-05  
**Status:** Approved via `/grill-me` Deep-Dive  
**Repository:** `https://github.com/pietzschke/westcode-patchbot`

---

## 1. Intent & Why

Westcode operates **17+ customer and internal projects** across **23 virtual machines** (defined as OpenTofu stacks in `westcode-infra`), **37 AWS ECR repositories**, and **30+ `westcoder/*` GitHub repositories**.

Our initial prototype (v1) focused on automated host rollouts and displayed raw scanner output. In practice, that created three problems:
1. **Live host mutation via SSH is undesirable:** Patchbot must never SSH into production VMs or mutate hosts directly. Humans (or existing CI pipelines after PR merge) perform the actual patching.
2. **Raw scanner output causes alert fatigue:** An unfiltered Trivy scan across local repositories yields ~2,000 raw CVEs, making it impossible to see on arrival whether urgent action is actually needed today.
3. **Missing project & ownership context:** A security finding or update is only actionable if the system knows **which active project** it belongs to (linking Notion projects, GitHub repos, containers, and hosts), **how complex the fix is** (*Einfacher Fix* vs. *Komplexer Eingriff*), **which developer in the team knows that code best**, and **whether a merged fix is actually running live on the server**.

**Westcode Patchbot v2** is an intelligent **Security & Update Triage Control Plane** that:
- Continuously links **active Notion Projects ↔ GitHub Repositories ↔ Docker/ECR Containers ↔ Live Hosts** inside Patchbot.
- Runs a **daily research & vulnerability scan** combined with a **Claude AI Triage & Code-Patching Engine** that checks code reachability, reads changelogs for breaking changes, filters out unexploitable noise, classifies findings into **Einfache Fixes (Quick Wins)** vs. **Komplexe Eingriffe (Deep Dives)**, reuses existing Dependabot/Renovate PRs (enriching them with a Claude comment) or automatically prepares a **ready Fix-PR** / **Draft-PR with application code patches** on GitHub.
- Keeps routine **non-security dependency updates (no CVE)** out of the alarm loop in a quiet **„Wartungs-Updates“** list (where PRs can be triggered on click).
- Matches the best responsible person (Infrastructure team for OS/host layers; the most recent Git author on the affected files for application layers, falling back to the Notion project owner) and notifies them exclusively via **personal Slack DM**.
- Enforces **3-stage Grace Periods** (`24h Sichtung` → `48h Einfacher Fix / 7d Komplexer Eingriff` → `24h Live-Gang nach PR-Merge`), escalating to the shared Team Slack channel if a stage expires, and **only marks a finding as resolved once the read-only host agent confirms the fix is running live on the VM**.

---

## 2. Goals, Non-Goals, and Anti-Goals

### Goals
1. **1-Second Dashboard Clarity (Status-Ampel):** Opening the dashboard immediately answers whether urgent action is required today (**Rot**), everything open is actively being worked on within its grace period (**Gelb**), or the fleet is clean (**Grün**).
2. **Project-Centric Asset Graph in Patchbot (Active Notion Filter):** Sync projects with active/maintenance status from Westcode's **Notion database** (plus per-project `is_monitored` toggle in Patchbot so archived projects never trigger scans or Slack DMs) and link them inside Patchbot to **GitHub repositories**, **containers**, and **hosts** (e.g., bundling `mdb.westcode.de`, `converter.westcode.de`, `westcoder/materialdatenbank`, and `westcoder/wuerth-converter` under **Würth**), with an **"Unzugeordnete Assets" inbox** and auto-match suggestions.
3. **Read-Only Live Host Telemetry (Including `:main` Tag Verification):** Each VM reports its live OS version, kernel/reboot flag, upgradable `apt` packages, and running container metadata (`RepoDigests` sha256, `Image.Created` build timestamp, and `/opt/<app>` Git `HEAD` commit SHA + `git_clean` flag) via a strictly read-only outbound push agent (`POST /api/agent/report`).
4. **Daily Research & Claude AI Triage + Smart PR Reuse/Creation:**
   - Scan CVE/Advisory databases (OSV.dev, GitHub Advisory Database, Trivy, Ubuntu/Debian Security Notices) once daily at `07:00 Europe/Berlin` (plus on demand).
   - **Proactive Triage & Slack-DMs only for Security (CVEs) & EOL:** Routine updates without CVEs are listed quietly under **„Wartungs-Updates“** without Slack DMs or 24h timers.
   - Use **Claude (`claude-sonnet-4-6`)** to inspect the repository code and changelogs: filter out unexploitable/dev-only noise (`FILTERED_IRRELEVANT`) and split actionable security findings into **Einfache Fixes** vs. **Komplexe Eingriffe**.
   - **Dependabot/Renovate Synergy:** If an open Dependabot/Renovate PR already covers the affected package, reuse that PR and post Claude's German triage analysis as a PR comment. If no PR exists (or if breaking changes require code edits), open a **Fix-PR** (`SIMPLE`) or a **Draft-PR where Claude also patches the affected application code** (`COMPLEX`).
5. **Context-Aware Ownership, 3-Stage Grace Periods & Slack-Only Alerting:**
   - Route OS/Infrastructure findings to the designated Infrastructure owners; route Application/Repo findings to the developer who most recently touched the affected files in Git (fallback: Notion project owner).
   - **Single Notification Channel (Slack Bot Only):** No Zammad tickets and no email digests. All notifications go through the Slack Bot (personal DM at T+0h + Team Slack channel on escalation or High/Critical risk dismissal).
   - **Transparent Dismissal / Snooze:** Marking a finding as **„Nicht betroffen“** or **„Zurückstellen (Snooze 14/30 Tage)“** requires a mandatory short justification; for `CRITICAL` and `HIGH` CVEs, the Slack Bot posts a brief transparency note to the Team Slack channel (four-eyes principle).
6. **Single-Tenant Microsoft Entra ID OAuth2 Login:**
   - Authenticate users into the Patchbot web app via Westcode's Single-Tenant **Microsoft Entra ID (OIDC / OAuth2 with PKCE)** using `@westcode.de` accounts (matching `westcode-hub`), automatically mapping the logged-in browser user 1:1 to their `TeamMember` record, Notion identity, and Slack user.

### Non-Goals
- Replacing CircleCI, Dependabot/Renovate, or OpenTofu (`westcode-infra`).
- Zammad or email alerting (replaced completely by the Slack Bot + Dashboard).
- Editing the Notion database from within Patchbot.

### Anti-Goals (Must Never Happen)
- **No SSH from Patchbot & No Live Host Patching:** Patchbot must never open SSH connections to hosts or execute mutating commands on production VMs.
- **No Alert Fatigue:** Never send Slack DMs or start 24h escalation timers for non-CVE routine updates or unverified/dev-only scanner findings.
- **No "Premature Done" on PR Merge:** A merged PR in GitHub must never close a finding while the production VM still runs the old container image or package.

---

## 3. Constraints & Technical Decisions

- **Technology Stack:**
  - **Backend:** Python 3.12+, Django 5.2, Django REST Framework (`backend/`).
  - **Authentication:** Single-Tenant Microsoft Entra ID OAuth2 (`MICROSOFT_TENANT_ID`, `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, PKCE enabled, restricted to `@westcode.de`), with a test/dev bypass session helper when running local unit tests.
  - **Frontend:** Angular 22 standalone components with Signals, official Westcode branding (`frontend/`).
  - **Host Telemetry Agent:** Python 3.8+ standard-library-only script (`agent/patchbot_agent.py`), invoked by a read-only `systemd` timer (`ProtectSystem=strict`).
  - **AI Engine:** Anthropic Python SDK (`anthropic`) using Claude (`claude-sonnet-4-6` by default, configurable via `PATCHBOT_CLAUDE_MODEL`).
  - **Integrations:**
    - **Notion API (`2022-06-28`):** Read-only sync of active projects from the Westcode Projects database (`NOTION_API_KEY`, `NOTION_PROJECTS_DATABASE_ID`).
    - **GitHub (`gh` CLI / REST & GraphQL API):** Repo cloning/worktrees, PR comment enrichment on existing Dependabot/Renovate PRs, Fix-PR / Draft-PR creation, CI status checks, `git log` / `git blame` ownership analysis (`GITHUB_TOKEN`).
    - **Slack API (`SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_TEAM_CHANNEL_ID`):** User lookup by `@westcode.de` email (`users.lookupByEmail`), direct messages (`chat.postMessage`), and interactive button callbacks (`Ich bin dran`, `Snooze / Nicht betroffen`).

---

## 4. System Architecture & Data Model

### 4.1 Domain 1: `inventory` (Project Graph, Assets, Entra Auth & Team Directory)

#### `TeamMember`
Linked 1:1 to the Django `User` authenticated via Microsoft Entra ID (`@westcode.de`):
- `id`: AutoField / UUID
- `user`: `OneToOneField(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=SET_NULL)`
- `name`: `str` (e.g., `"Moritz Pietzschke"`)
- `email`: `str` (unique, `@westcode.de` address — matches Entra ID login, Notion person email, and Slack `users.lookupByEmail`)
- `github_username`: `str` (unique, e.g., `"pietzschke"`)
- `git_commit_emails`: `JSONField[list[str]]` (optional additional git author email aliases)
- `slack_user_id`: `str` (auto-resolved via Slack `users.lookupByEmail`)
- `layers`: `JSONField[list[str]]` (subset of `["infrastructure", "application"]`)
- `is_default_infra_owner`: `bool`
- `is_active`: `bool`

#### `Project`
Synced from the Notion database (filtered to active/maintenance status in Notion) and toggleable in Patchbot:
- `id`: AutoField / UUID
- `slug`: `str` (unique, e.g., `"wuerth"`, `"ses-sandmann"`, `"westcode-service"`)
- `name`: `str` (e.g., `"Würth"`)
- `notion_page_id`: `str | None` (unique when present)
- `notion_status`: `str` (e.g., `"Aktiv"`, `"Wartung"`)
- `is_monitored`: `bool` (default `True` for active Notion projects; when `False`, excluded from daily scans and Slack DMs)
- `customer_name`: `str`
- `owner`: `ForeignKey(TeamMember, null=True, on_delete=SET_NULL)` (resolved from Notion via `@westcode.de` email)
- `logo_key`: `str` (default `"westcode"`)
- `last_notion_synced_at`: `DateTimeField | None`

#### Assets Linked to a `Project` in Patchbot
1. **`RepositoryAsset` (`westcoder/*` GitHub repository):**
   - `full_name`: `str` (unique, e.g., `"westcoder/materialdatenbank"`, `"westcoder/wuerth-converter"`)
   - `default_branch`: `str` (default `"main"`)
   - `project`: `ForeignKey(Project, null=True, blank=True, related_name="repositories")`
   - `suggested_project`: `ForeignKey(Project, null=True, blank=True, related_name="suggested_repositories")`
   - `last_scanned_at`: `DateTimeField | None`
   - `last_commit_sha`: `str`
2. **`Host` (VM from `westcode-infra` + live telemetry):**
   - `slug`, `hostname`, `provider`, `stack_name`
   - `project`: `ForeignKey(Project, null=True, blank=True, related_name="hosts")`
   - `suggested_project`: `ForeignKey(Project, null=True, blank=True, related_name="suggested_hosts")`
   - `declared_image`, `os_distro`, `os_version`, `kernel_version`
   - `is_os_eol`: `bool`, `reboot_required`: `bool`
   - `agent_token_hash`: `str`, `last_seen_at`: `DateTimeField | None`
3. **`HostContainer` (Running container reported by read-only host agent):**
   - `host`: `ForeignKey(Host, related_name="containers")`
   - `container_id`, `name`, `image_tag`, `image_id`
   - `repo_digests`: `JSONField[list[str]]` (the `sha256` manifest digests)
   - `image_created_at`: `DateTimeField | None` (parsed from `docker inspect` `Image.Created`, crucial for verifying `:main` images built after `pr_merged_at`)
   - `working_dir`, `compose_service`: `str`
   - `git_head_sha`: `str` (from `git -C /opt/<dir> rev-parse HEAD`)
   - `git_clean`: `bool | None` (from `git -C /opt/<dir> status --porcelain`)
   - `project`: `ForeignKey(Project, null=True, blank=True, related_name="containers")`
   - `repository`: `ForeignKey(RepositoryAsset, null=True, blank=True, related_name="running_containers")`
4. **`HostPackage` (Upgradable `apt` package reported by host agent):**
   - `host`: `ForeignKey(Host, related_name="packages")`
   - `name`, `installed_version`, `candidate_version`, `is_security_update`: `bool`

---

### 4.2 Domain 2: `research` (Daily CVE Scanner, Claude Triage & PR Reuse/Creation)

1. **Candidate Collection (Active Projects Only):**
   - Scans only `RepositoryAsset` and `Host` records belonging to `Project(is_monitored=True)`.
   - **Security Candidates (Trigger Triage + PR + Slack DM):**
     - Application dependencies with CVEs (`MEDIUM`, `HIGH`, `CRITICAL`) from Trivy / OSV.dev / GitHub Advisory DB, clustered by `(repository, package_name, fixed_version)`.
     - Host `apt` security packages (`is_security_update=True`), `reboot_required=True`, and `is_os_eol=True`.
   - **Routine Maintenance Updates (Quiet List Only):**
     - Non-CVE dependency updates / open Dependabot & Renovate PRs without CVEs are stored as `MaintenanceUpdate` items (shown in a separate **„Wartungs-Updates“** tab without Slack DMs or 24h timers, with a 1-click button to prepare/open a PR when desired).
2. **Claude AI Reachability & Complexity Analysis:**
   - Checks whether the vulnerable package/function is actually reachable in production code vs. dev/test-only (`is_relevant: bool`). Irrelevant findings are stored as `FILTERED_IRRELEVANT` (zero alerts).
   - Classifies relevant findings into:
     - `SIMPLE` (**Einfacher Fix**, 48h implementation grace period): Compatible patch/minor bump or `apt` security update / reboot.
     - `COMPLEX` (**Komplexer Eingriff**, 7d implementation grace period): Breaking changes affecting call sites in the repo, major framework upgrade, or Ubuntu EOL server migration.
3. **Smart GitHub PR Reuse & Creation:**
   - **Case 1 (Existing Dependabot/Renovate PR exists):** Links the existing PR (`pr_number`, `pr_url`) and posts a structured comment onto that PR with Claude's German reachability & changelog analysis. If `complexity == "COMPLEX"` and code edits are required, Claude checks out the PR branch (or opens a companion Draft-PR) and commits the necessary application code adjustments.
   - **Case 2 (No PR exists yet, Application Repo):** Creates an isolated `git worktree` on `patchbot/<package>-<target_version>`.
     - For `SIMPLE`: updates manifest/lockfile and opens a **ready PR**.
     - For `COMPLEX`: runs Claude's code-patching loop on `affected_files` inside the worktree and opens a **Draft-PR**.
   - **Case 3 (Ubuntu EOL Host in `westcode-infra`):** Optionally prepares a Draft-PR in `westcoder/westcode-infra` updating the server image / migration checklist.

---

### 4.3 Domain 3: `triage` (Ownership, 3-Stage Grace Periods, Live Verification & Dismissal)

#### Ownership Matching Cascade
1. **`layer == "INFRASTRUCTURE"`** (`apt` security updates, kernel reboot, Ubuntu EOL):
   - Assigned to the active `TeamMember` with `is_default_infra_owner=True` (or `"infrastructure"` layer role).
2. **`layer == "APPLICATION"`**:
   - **Priority 1:** Most recent active human `TeamMember` who modified the affected files / manifest in Git (`git log` / `git blame`, skipping `dependabot`, `renovate`, `github-actions`).
   - **Priority 2 (Fallback):** `project.owner` synced from Notion.

#### 3-Stage Grace Periods & Live Verification
1. **Stage 1 – Sichtung (`NEW`):** **24h** until the assignee clicks **„Ich bin dran“** (in Slack or Web-UI, authenticated via Entra ID) → moves to `IN_PROGRESS`.
2. **Stage 2 – Umsetzung (`IN_PROGRESS`):** **48h** (`SIMPLE`) or **7d** (`COMPLEX`) from `acknowledged_at`:
   - **For Application Repo findings:** Advances to `PR_MERGED_WAITING_LIVE` when the linked GitHub PR is merged.
   - **For Host `apt` / Kernel Reboot findings (no Git PR needed):** Advances directly to `VERIFIED_LIVE` as soon as the read-only host agent reports that the security `apt` packages are installed and `reboot_required == False`.
3. **Stage 3 – Live-Gang (`PR_MERGED_WAITING_LIVE`):** **24h** from `pr_merged_at`:
   - Advances to `VERIFIED_LIVE` **only** when all linked `HostContainer` instances for that project/repository satisfy at least one of:
     - `image_created_at > pr_merged_at` (proves the container image running on the VM was built after the PR was merged, even when using mutable `:main` tags), OR
     - `git_head_sha` in `/opt/<app>` is an ancestor of / equal to the merge commit SHA, OR
     - `image_tag` / `oci_revision` matches `target_version`.
   - If 24h pass after PR merge and the live host still runs the pre-merge container, Patchbot escalates (`escalation_stage = 3`): *„PR #... wurde vor >24h gemergt, läuft auf `mdb.westcode.de` aber noch nicht live!“*

#### Dismissal & Snooze („Nicht betroffen“ / „Zurückstellen“)
- Requires a **mandatory justification text** (`dismissal_reason`) and a mode:
  - `SNOOZED` (`snoozed_until = now() + 14d` or `30d`) — automatically re-opens to `NEW` when the snooze expires if still present.
  - `DISMISSED_NOT_EXPLOITABLE` — permanently muted for `(project, vulnerability_id, package_name)`.
- **Four-Eyes Transparency Rule:** Whenever a `CRITICAL` or `HIGH` finding is snoozed or dismissed, the Slack Bot posts a concise info message to `SLACK_TEAM_CHANNEL_ID` (*„ℹ️ @Moritz hat CVE-2026-xxxx in Projekt Würth als nicht ausnutzbar markiert: ‚...‘“*).

---

### 4.4 Frontend UI Specification (`frontend/`)

1. **Top Navigation Bar:**
   - Official Westcode wordmark + signet logo (`westcode-schwarz.svg`).
   - Four primary tabs:
     1. **Triage-Dashboard** (`/`) — includes sub-switch for **„Sicherheits-Triage“** vs. **„Wartungs-Updates (ohne CVE)“**
     2. **Projekte & Zuordnung** (`/projects`) — Notion sync + „Unzugeordnete Assets“-Inbox + `Projekt ↔ Repo ↔ Container ↔ Host` editor
     3. **Live-Hosts (23)** (`/hosts`) — Read-only telemetry status, `Image.Created` / Digest / `/opt` Git status, manual runbooks, and agent token generator
     4. **Team & Schichten** (`/team`) — `TeamMember` directory (`@westcode.de` ↔ GitHub handle ↔ Slack ID ↔ Layer role)
   - Right side: Logged-in **Entra ID User Badge** (`@westcode.de`) + **„Scan & Sync starten“** button.

2. **Triage-Dashboard (`/`) Layout:**
   - **Full-Width Status-Ampel Banner:**
     - **ROT (`Handlungsbedarf`):** Escalated findings, unacknowledged `NEW` findings, or overdue `PR_MERGED_WAITING_LIVE` rollouts.
     - **GELB (`In Bearbeitung`):** All active findings have an owner (*„Ich bin dran“*) within their grace period.
     - **GRÜN (`Alles im grünen Bereich`):** Zero open security findings and all merged fixes are verified live on the VMs.
   - **Grouping & Filter Bar:** Toggle **„Nach Aufwand (Quick Wins / Komplex)“** vs. **„Nach Projekt gruppiert (Würth, SES, …)“** + Filter **„Nur meine Aufgaben“**.
   - **Master-Detail Split View:**
     - Left: **1. Einfache Fixes (48h)**, **2. Komplexe Eingriffe (7d)**, **3. Gemergt – Wartet auf Live-Gang (24h)**.
     - Right (Sticky 45°-Cut Detail Panel): Claude reachability & breaking-change analysis, affected file paths/lines, Assignee + Grace-Period countdown, **„Ich bin dran“** / **„Snooze / Nicht betroffen (mit Begründung)“** controls, linked PR/Draft-PR badge, and live host container verification table (`Image gebaut am ...` vs. `PR gemergt am ...`).
