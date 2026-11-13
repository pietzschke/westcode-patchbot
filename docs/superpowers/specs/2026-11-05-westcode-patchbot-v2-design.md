# Westcode Patchbot v2 — Security & Update Triage Control Plane (Design Specification)

**Date:** 2026-11-05 (Refinement v2.1)  
**Status:** v2.1 — refinement of the `/grill-me`-approved v2.0; all decisions in §10 resolved  
**Repository:** `https://github.com/pietzschke/westcode-patchbot`

> Changes versus v2.0 are summarized in **Appendix A**. Items marked **(D-n)** reference a resolved decision in §10.

---

## 1. Intent & Why

Westcode operates **17+ customer and internal projects** across **23 virtual machines** (OpenTofu stacks in `westcode-infra`), **37 AWS ECR repositories**, and **30+ `westcoder/*` GitHub repositories**.

The v1 prototype focused on automated host rollouts and raw scanner output. In practice that created five problems:

1. **Live host mutation is undesirable.** v1 still contains an agent job channel (`compose_update`, `apt_upgrade`, `host_reboot`), a rollout orchestrator and a PR auto-merge hook. Patchbot must never change production hosts or merge code; humans and existing CI pipelines do that.
2. **Raw scanner output causes alert fatigue.** An unfiltered Trivy scan yields ~2,000 raw CVEs; nobody can tell at a glance whether action is needed today.
3. **Missing project and ownership context.** A finding is only actionable if Patchbot knows the **active project** it belongs to (Notion ↔ GitHub ↔ containers ↔ hosts), **how complex** the fix is (*Einfacher Fix* vs. *Komplexer Eingriff*), **who** should handle it, and **whether a merged fix actually runs live**.
4. **Silent failures look like "all clear".** v1 swallows scanner errors (`except Exception: return []`), scans a developer's local checkout path, and synthesizes container records for hosts without an agent. A broken scan or a dead agent therefore looks identical to a clean fleet.
5. **Container images are not scanned.** v1 scans repository manifests only; OS packages inside the 37 ECR images (base-image CVEs) are invisible.

**Westcode Patchbot v2** is a **read-only Security & Update Triage Control Plane** that:
- Links **active Notion projects ↔ GitHub repositories ↔ running containers ↔ hosts**.
- Runs a **daily scan** (repository dependencies, running container images, host OS packages), enriches findings with exploit signals (CISA KEV, EPSS), and uses **Claude** to assess reachability and fix complexity — **as a recommendation gated by deterministic policy**, never as the sole reason to hide a severe CVE.
- Reuses existing Dependabot/Renovate PRs (adding a triage comment) or prepares a **Fix-PR** (deterministic manifest/lockfile bump) or a **Draft-PR** (Claude-written code changes, always human-reviewed).
- Keeps non-security updates in a quiet **„Wartungs-Updates“** list.
- Assigns each finding to one person and notifies via **Slack only** (personal DM, team channel on escalation).
- Enforces **3-stage grace periods** and closes a finding **only after verified live rollout**.
- Shows **„Datenlage unvollständig“** instead of green whenever scans fail or agents are stale.

---

## 2. Goals, Non-Goals, Anti-Goals, Success Criteria

### Goals
1. **1-second clarity (Status-Ampel):** The dashboard answers immediately: urgent action today (**Rot**), everything open is owned and within its grace period (**Gelb**), fleet clean *and data complete* (**Grün**), or Patchbot cannot vouch for the state (**Grau – Datenlage unvollständig**).
2. **Project-centric asset graph:** Projects synced read-only from Notion (active/maintenance), per-project `is_monitored` toggle, linked to repositories, containers and hosts; **„Unzugeordnete Assets“ inbox** with auto-match suggestions that a human confirms.
3. **Read-only, push-only host telemetry:** Each VM reports OS, kernel, reboot flag, installed + upgradable packages, apt list freshness, and running containers (digest, OCI labels, build timestamp, `/opt/<app>` Git HEAD) via `POST /api/agent/report/`. The agent never receives or executes instructions from the server.
4. **Daily research and AI-assisted triage:**
   - Scan once daily at `07:00 Europe/Berlin` plus on demand.
   - Slack DMs and timers **only** for security findings (CVE) and host EOL/reboot items; routine updates go to „Wartungs-Updates“ silently.
   - Claude assesses reachability, changelog breaking changes and complexity; a **deterministic policy gate** decides whether a finding may be suppressed.
   - Smart PR handling: reuse bot PRs, otherwise Fix-PR (`SIMPLE`) or Draft-PR (`COMPLEX`).
5. **Ownership, grace periods, Slack-only alerting:** One assignee per finding, deadlines in working days, aggregated DMs, idempotent escalation, mandatory justification for dismiss/snooze, transparency post for HIGH/CRITICAL.
6. **Single-tenant Microsoft Entra ID login** (OIDC authorization code + PKCE), identity bound to `TeamMember` via the immutable Entra object ID.

### Non-Goals
- Replacing CircleCI, Dependabot/Renovate, or OpenTofu (`westcode-infra`).
- Zammad tickets or email alerting.
- Editing Notion from Patchbot.
- Scanning projects/assets not linked to a monitored project.
- Scanning LOW/UNKNOWN severity CVEs or CVEs without an upstream fix (shown as count only, no finding).

### Anti-Goals (must never happen)
1. **No host mutation and no command channel:** Patchbot never opens SSH connections, the agent contains no mutating code path, and the agent ignores the body of every server response.
2. **No auto-merge:** Patchbot never merges, approves, or pushes to a default branch.
3. **No alert fatigue:** No DMs or timers for non-CVE updates; at most **one aggregated DM per person per scan run**; each escalation is posted exactly once per stage.
4. **No premature „done“:** A merged PR never closes a finding while any linked production container still runs pre-fix code.
5. **No silent suppression of severe CVEs by AI:** Claude alone can never hide a `CRITICAL` or CISA-KEV-listed finding.
6. **No false green:** A failed scan, a stale agent, or missing data can never produce **Grün**.

### Success Criteria (measured after 4 weeks of operation)
- New security findings stay manageable after the initial backlog (target: ≤ 5 new findings per person per week).
- ≥ 90 % of merged fix PRs reach `VERIFIED_LIVE` without manual intervention.
- Zero findings closed while the vulnerable version was still running (spot-checked via image rescan).
- Zero duplicate DMs or duplicate escalation posts for the same finding and stage.

---

## 3. Constraints & Technical Decisions

### 3.1 Stack
- **Backend:** Python 3.12+, Django 5.2, Django REST Framework (`backend/`), PostgreSQL in production (SQLite for local dev/tests).
- **Frontend:** Angular 22 standalone components with Signals, Westcode branding (`frontend/`).
- **Host agent:** Python 3.8+ stdlib-only script (`agent/patchbot_agent.py`), systemd **oneshot** service triggered by a timer (every 15 min).
- **AI engine:** Anthropic Python SDK, default model `claude-sonnet-5-5`, configurable via `PATCHBOT_CLAUDE_MODEL`. Structured outputs (`output_config.format` with a JSON schema; forced `tool_choice` is rejected by current models), additionally validated by Patchbot; static system prompt with prompt caching; prompt version stored per analysis. Refusals (CVE analysis can trip safety classifiers) use the server-side fallback (`fallbacks: "default"`); a refusal of the whole chain leaves the finding `UNTRIAGED`.
- **Scanner:** Trivy as the single vulnerability scanner (its DB aggregates GitHub Advisory, ecosystem advisories and Ubuntu/Debian security data) — no separate OSV/GHSA/USN integrations.
- **Exploit signals:** CISA KEV JSON feed (daily) and FIRST EPSS API (daily), cached locally.

### 3.2 Integrations
| Integration | Purpose | Credential | Scope |
|---|---|---|---|
| Microsoft Entra ID | Web login | `MICROSOFT_TENANT_ID`, `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` | Single tenant, OIDC `openid profile email` |
| Notion API (`2022-06-28`) | Read-only project sync | `NOTION_API_KEY`, `NOTION_PROJECTS_DATABASE_ID` | Read content + read user info incl. email |
| GitHub **App** on org `westcoder` | Clone, PR read/create, comments, CI status, `git log` ownership, webhooks (`pull_request`, `check_suite`) | App ID + private key, `GITHUB_WEBHOOK_SECRET` | `contents: write` (only `patchbot/*` branches via ruleset), `pull_requests: write`, `checks: read`, `metadata: read`; **no** `workflows` permission, **no** admin |
| AWS ECR | Pull running image digests for scanning | IAM role `patchbot-ecr-read` | `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` only |
| Slack | DMs, team channel, buttons (HTTP interactivity) **(D-1)** | `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `SLACK_TEAM_CHANNEL_ID` | `chat:write`, `users:read`, `users:read.email`, `im:write` |
| Anthropic | Triage + code patching | `ANTHROPIC_API_KEY` | — |

### 3.3 Runtime Topology
- **`web`**: Django/DRF behind the reverse proxy. Entra-protected; the agent endpoint is reachable from the VMs.
- **Public ingress (D-1):** the reverse proxy exposes **only** `POST /api/webhooks/slack/interactions/` and `POST /api/webhooks/github/` to the internet (path allowlist, request body limit 1 MB, rate limit). Every other path stays internal. Webhook handlers verify signatures, persist the event, and return `200` within 3 s; processing happens in `worker`.
- **`worker`**: one long-running process that hosts (a) the scheduler (daily scan 07:00, grace-period evaluator every 15 min, PR reconciliation poll every 60 min as webhook fallback, KEV/EPSS refresh, Notion sync), (b) the job queue for scans, webhook events and PR preparation. Jobs are DB-backed with a row lock so only one scan runs at a time.
- **`sandbox`**: ephemeral container per Claude code-patching run (see §5.5).
- Repository mirror cache on a persistent volume (`PATCHBOT_REPO_CACHE`), never a developer's local path.

---

## 4. Data Model — Inventory & Fleet

### 4.1 Domain `inventory` — Team, Projects, Repositories

#### `TeamMember`
- `user`: `OneToOneField(User, null=True, on_delete=SET_NULL)`
- `entra_object_id`: `str | None` (unique; immutable Entra `oid` — the identity key after first login)
- `name`, `email` (unique, `@westcode.de`; used for first-login binding, Notion owner matching, Slack lookup)
- `github_username` (unique, nullable), `git_commit_emails`: `list[str]`
- `slack_user_id` (auto-resolved via `users.lookupByEmail`, nullable)
- `layers`: subset of `["infrastructure", "application"]`
- `is_default_infra_owner`: `bool` (exactly one active member must have it; enforced by validation)
- `is_admin`: `bool` (may edit team, project assignments, monitoring toggles, agent tokens)
- `is_active`: `bool`

#### `Project`
- `slug` (unique), `name`, `customer_name`, `logo_key`
- `notion_page_id` (unique when present), `notion_status`, `notion_missing`: `bool`, `last_notion_synced_at`
- `owner`: FK `TeamMember` (from Notion people property via email)
- `is_monitored`: `bool`
- **Precedence rules:**
  - Source: Notion data source „📂 Projects“ — properties `Name` (title), `Status` (status), `Project Manager` (person → `owner` via email), `Client` (relation → `customer_name` via the related page title), `Intern` (checkbox → `is_internal`).
  - Status groups (settings): active = `In progress`, `In maintenance`; not started = `Not started`; closed = `Done`, `GESPERRT!` (same classification as Projectory).
  - New project from Notion: `is_monitored = status ∈ active`.
  - Status becomes not started or closed → `is_monitored = False` (forced).
  - First activation (`Not started` → active) → `is_monitored = True`.
  - Reactivation (closed → active) → `is_monitored` unchanged (a human decides).
  - Manual toggle in Patchbot persists across syncs while the project stays active.
  - Page no longer returned by Notion → `notion_missing = True`, `is_monitored = False`, findings kept but frozen.
  - Unknown statuses are logged, reported in the sync result and treated as inactive.
- Turning monitoring off moves open findings of that project to `SUPPRESSED_UNMONITORED` (no DMs, no timers); turning it on re-opens them as `NEW`.

#### `RepositoryAsset`
- `full_name` (unique), `default_branch`, `is_archived` (from GitHub)
- `project`, `suggested_project` (FKs, nullable)
- `deployment_mode`: `CONTAINER` | `HOST_CHECKOUT` | `NONE` | `UNKNOWN` (default `UNKNOWN`)
  - `NONE` (libraries, tooling): set explicitly by a human; findings resolve on merge (`RESOLVED_NO_DEPLOYMENT`).
  - `UNKNOWN`: merged findings stay in `PR_MERGED_WAITING_LIVE` and the detail panel asks for a decision — never auto-resolved.
- `has_bot_updates`: `bool` (Renovate/Dependabot config detected)
- `last_scanned_at`, `last_scanned_commit_sha`

#### Auto-Match Suggestions
- Signals, in order of strength: `oci_source` label → repository (deterministic, auto-linked); compose project / `working_dir` name; ECR repository name; hostname prefix; `stack_name`; curated alias table (e.g. `materialdatenbank`, `wuerth-converter` → `wuerth`).
- Suggestions populate `suggested_project` only; a human confirms in the „Unzugeordnete Assets“ inbox. Exception: the `oci_source` link between container and repository is deterministic and set automatically.

### 4.2 Domain `fleet` — Hosts & Telemetry

#### `Host`
- `slug`, `hostname`, `provider`, `stack_name`, `declared_image` (from `westcode-infra`)
- `project`, `suggested_project` (FKs, nullable; a host may run containers of several projects — container links are authoritative, the host link only drives infra-finding display)
- `os_distro`, `os_version`, `os_eol_date` (static table per release), `kernel_version`, `reboot_required`
- `apt_lists_updated_at` (mtime of `/var/lib/apt/periodic/update-success-stamp`, fallback `/var/lib/apt/lists`)
- `agent_version`, `agent_token_hash`, `last_seen_at`
- Derived: `telemetry_fresh = last_seen_at > now − 60 min`

#### `HostContainer`
Replaced in full on every report; **only** created from agent reports — never synthesized.
- `host`, `container_id`, `name`, `compose_service`, `status`
- `image_tag`, `image_id`, `repo_digests: list[str]`
- `oci_revision` (`org.opencontainers.image.revision`), `oci_source` (`org.opencontainers.image.source`), `oci_title`
- `image_created_at` (display/heuristic only — never sufficient for verification)
- `working_dir`, `git_head_sha`, `git_clean`
- `project`, `repository` (FKs)
- `reported_at`

#### `HostPackage`
- `host`, `name`, `installed_version`, `candidate_version` (nullable), `is_security_update`, `source_pocket` (e.g. `jammy-security`)
- The agent reports **all installed packages** (`dpkg-query -W`) plus upgrade candidates from `apt-get -s dist-upgrade`, so verification compares the installed version against the fixed version instead of relying on the absence of an upgrade candidate.

---

## 5. Research Domain — Scanning, Triage, PRs

### 5.1 Scan Run & Health
- `ScanRun(started_at, finished_at, trigger: SCHEDULED|MANUAL, status: RUNNING|OK|PARTIAL|FAILED)`
- `TargetScan(scan_run, target_type: REPO|IMAGE|HOST, target_ref, status: OK|FAILED|SKIPPED, error, duration)`
- A failed `TargetScan` **never** clears findings for that target; previous findings stay untouched.
- Timeouts sized for real repositories (default 300 s per target); the Trivy DB is updated once per run before targets are scanned.

### 5.2 Candidate Sources (monitored projects only)
| Layer | Target | Source | Finding trigger |
|---|---|---|---|
| `APPLICATION` | Repository default branch (fresh checkout from mirror cache) | `trivy fs` on lockfiles/manifests | CVE with fix, severity ≥ MEDIUM |
| `CONTAINER_IMAGE` | Each distinct running digest reported by agents | `trivy image <repo>@<digest>` (ECR read role; public registries anonymously); cached per digest | OS/base-image CVE with fix, severity ≥ MEDIUM |
| `INFRASTRUCTURE` | Host | Agent report | Security-pocket upgrade pending; `reboot_required`; OS EOL past or ≤ 90 days away |

Application CVEs found in both repository and image are attributed to `APPLICATION` (the repository is where the fix happens); the image scan is then used for live verification (§6.4).

**Routine maintenance:** Open Renovate/Dependabot PRs that do not resolve any known CVE become `MaintenanceUpdate` items (quiet list, no DM, no timer).

### 5.3 Clustering & Deduplication
- **Finding key:** `(project, layer, target_ref, ecosystem, package_name)` — unique among open findings.
- `vulnerability_ids` accumulate inside the cluster; `target_version` = the lowest version fixing **all** CVEs in the cluster; `highest_severity`, `kev_listed`, `max_epss` are recomputed each scan.
- A later scan that raises `target_version` while `IN_PROGRESS` updates the finding, notifies the assignee once, and **does not reset** timers.
- A finding whose CVEs disappear from the scan **before** a PR merge goes to live verification (someone fixed it outside Patchbot) — it is not silently closed.
- A finding re-detected after `VERIFIED_LIVE` creates a new finding linked via `regression_of`.

### 5.4 Claude Triage & Policy Gate
**Input** (per cluster, cached by `(cluster_key, target_version, repo_commit_sha, prompt_version)`): advisory text, affected/fixed versions, manifest context (direct vs. transitive, dev vs. prod dependency from lockfile metadata), grep-based call-site hits for the package and vulnerable symbol, upstream changelog between current and target version. All external text is passed as clearly delimited, untrusted data.

**Output schema:**
```json
{
  "reachability": "REACHABLE | LIKELY_REACHABLE | UNLIKELY_REACHABLE | NOT_REACHABLE",
  "reachability_reason_category": "DEV_ONLY | TEST_ONLY | UNUSED_FEATURE | NO_CALL_SITE | OTHER",
  "complexity": "SIMPLE | COMPLEX",
  "confidence": 0.0,
  "summary_de": "…",
  "breaking_changes_de": "…",
  "affected_files": ["path:line"]
}
```

**Policy gate (deterministic, not Claude):** a finding becomes `FILTERED_IRRELEVANT` only if **all** hold:
1. `highest_severity != CRITICAL`, not `kev_listed`, and `max_epss < 0.10`;
2. Claude says `NOT_REACHABLE` with `confidence ≥ 0.8`;
3. the reason is backed by deterministic evidence: `DEV_ONLY`/`TEST_ONLY` confirmed by lockfile metadata, or `NO_CALL_SITE` confirmed by zero grep hits.

Otherwise the finding stays actionable; Claude's assessment is shown as a hint („Claude: vermutlich nicht erreichbar“) and a human can dismiss it with justification (§6.5).

- Filtered findings stay visible in the **„Automatisch gefiltert“** list and are re-evaluated when severity, KEV status or EPSS changes.
- Without an API key or on API failure: `complexity = COMPLEX`, `triage_status = UNTRIAGED`, finding treated as relevant — never filtered.
- Infrastructure findings skip Claude: apt security/reboot → `SIMPLE`; OS EOL → `COMPLEX`.

### 5.5 GitHub PR Engine
**Principles:**
- Patchbot never merges, approves, or pushes to default branches or to bot-owned branches.
- **Deterministic changes** (manifest/lockfile bump via the ecosystem's package manager) may go into a **ready PR**.
- **Any Claude-written code** goes into a **Draft-PR** labelled `patchbot:ai-generated`.
- Branch naming `patchbot/<package>-<target_version>`; one open Patchbot PR per finding.

**Cases:**
1. **Bot PR exists** (Renovate/Dependabot PR bumping the package to ≥ `target_version`): link it (`pr_source = BOT`) and post one triage comment (updated in place on re-analysis, never duplicated). If `COMPLEX` and code changes are needed, open a **companion Draft-PR** based on the bot branch — never push to the bot branch itself, because Renovate/Dependabot stop maintaining a PR once someone else pushes to it.
2. **No PR, `SIMPLE`:** deterministic bump in an isolated worktree → ready PR (`pr_source = PATCHBOT`). If the bump fails (resolver conflict), the finding is reclassified `COMPLEX`.
3. **No PR, `COMPLEX`:** Claude code-patching run in the sandbox → Draft-PR (`pr_source = PATCHBOT_AI`).
4. **Host OS EOL:** no PR in `westcode-infra`; the finding (`COMPLEX`, infra owner) carries a migration checklist as manual runbook (new image, data migration, DNS cut-over, decommission old VM) **(D-5)**. The GitHub App gets no access to `westcode-infra`.

**Code-patching sandbox:**
- The Claude tool-use loop runs in `worker`; the sandbox only executes the individual tool calls. The sandbox therefore holds no API key.
- Ephemeral container with only the worktree mounted; no Patchbot secrets, no Anthropic key, no GitHub token, no cloud credentials inside; `--cap-drop=ALL`, `no-new-privileges`, non-root user.
- Network egress only to the ecosystem's package registry (internal network + allow-listing egress proxy).
- Allowed tools: read/edit files inside the worktree (path-confined), run allow-listed commands (package-manager install with lifecycle scripts disabled, the project's test command).
- Limits: max 30 tool iterations, max 15 min, max token budget per run (configurable).
- **Diff gate after the run** (enforced by Patchbot, outside the sandbox): reject if the diff touches `.github/**`, `.circleci/**`, deployment/infra files, `*.env*`, matches secret patterns, or exceeds 500 changed lines. A rejected run leaves the finding `COMPLEX` without PR, with a note in the detail panel.
- Patchbot commits and pushes the validated diff with the GitHub App token.

### 5.6 Maintenance Updates
- `MaintenanceUpdate(project, repository, package_name, current_version, target_version, update_type: PATCH|MINOR|MAJOR, pr_number, pr_url, ci_status, summary_de, updated_at)`.
- Button **„Analyse anfordern“** runs Claude's changelog/breaking-change analysis on demand and posts it as a PR comment. No DMs, no timers.

---

## 6. Triage Domain — Lifecycle, Ownership, Verification, Notifications

### 6.1 `Finding` (lives in the `triage` app)
- **Identity & context:** `project`, `layer`, `repository | host | image_digest`, `ecosystem`, `package_name`, `current_version`, `target_version`, `vulnerability_ids`, `highest_severity`, `kev_listed`, `max_epss`, `regression_of`.
- **Triage:** `triage_status (TRIAGED|UNTRIAGED)`, `reachability`, `complexity`, `confidence`, `summary_de`, `breaking_changes_de`, `affected_files`, `analysis_prompt_version`.
- **PR:** `pr_number`, `pr_url`, `pr_is_draft`, `pr_source (BOT|PATCHBOT|PATCHBOT_AI)`, `ci_status`, `merge_commit_sha`, `pr_merged_at`.
- **Lifecycle:** `state`, `assignee`, `assigned_reason_de`, `discovered_at`, `acknowledged_at`, `verified_live_at`, `deadline_at`, `escalated_stage` (highest stage already escalated), `dismissal_mode`, `dismissal_reason`, `dismissed_by`, `snoozed_until`, `manual_runbook`.

`FindingEvent(finding, at, actor: TeamMember | null, source: WEB|SLACK|SYSTEM, from_state, to_state, note)` — append-only audit log for every transition, assignment, dismissal and escalation.

PR merge detection: GitHub `pull_request` webhook (`closed` + `merged == true`) sets `merge_commit_sha`/`pr_merged_at`; the hourly reconciliation poll catches missed deliveries **(D-1)**. Webhook deliveries are deduplicated by `X-GitHub-Delivery`.

### 6.2 States & Transitions
| State | Meaning | Deadline | Leaves to |
|---|---|---|---|
| `NEW` | Assigned, not acknowledged | 1 working day **(D-2)** | `IN_PROGRESS`, `PR_MERGED_WAITING_LIVE`, `SNOOZED`, `DISMISSED` |
| `IN_PROGRESS` | Owner acknowledged | `SIMPLE`: 2 working days; `COMPLEX`: 5 working days | `PR_MERGED_WAITING_LIVE` (app/image), `VERIFIED_LIVE` (host), `SNOOZED`, `DISMISSED` |
| `PR_MERGED_WAITING_LIVE` | Fix merged, not yet confirmed live | 1 working day from `pr_merged_at` | `VERIFIED_LIVE`, `RESOLVED_NO_DEPLOYMENT` |
| `VERIFIED_LIVE` | Confirmed running | — | terminal (regression → new finding) |
| `RESOLVED_NO_DEPLOYMENT` | Repo `deployment_mode = NONE`, merged | — | terminal |
| `SNOOZED` | Deferred 14/30 days | `snoozed_until` | `NEW` on expiry if still detected, otherwise live verification |
| `DISMISSED` | „Nicht betroffen“ | — | `NEW` if severity rises, KEV-listed, or after 180 days |
| `FILTERED_IRRELEVANT` | Policy gate passed | — | `NEW` if signals change |
| `SUPPRESSED_UNMONITORED` | Project not monitored | — | `NEW` when monitoring is re-enabled |

- **Working-day clock (D-2):** Mon–Fri in `Europe/Berlin`, excluding a configurable holiday list (`PATCHBOT_HOLIDAYS`, default: NRW public holidays). A deadline of *n* working days ends at the same local time *n* working days later; a finding created on a weekend/holiday starts counting at 08:00 of the next working day.
- **KEV exception (D-2):** findings that are `CRITICAL` **and** `kev_listed` use wall-clock time (`NEW` 24 h; `IN_PROGRESS` 48 h for `SIMPLE` / 7 days for `COMPLEX`; `PR_MERGED_WAITING_LIVE` 24 h) and escalate immediately, also outside working hours.
- A `NEW` finding whose PR is merged before acknowledgement moves directly to `PR_MERGED_WAITING_LIVE` (implicit acknowledgement, logged).
- Any active team member may click „Ich bin dran“; doing so reassigns the finding to them (logged).
- `POST /api/findings/<id>/extend/` extends the current deadline once per stage by the stage's original length, with mandatory reason (logged, visible in the detail panel).

### 6.3 Ownership Cascade
1. **`INFRASTRUCTURE`** → active `TeamMember` with `is_default_infra_owner`.
2. **`CONTAINER_IMAGE`** → `project.owner` (base-image maintenance belongs to the project).
3. **`APPLICATION`**:
   - `SIMPLE` (manifest/lockfile only) → `project.owner`. The last person who touched a lockfile is noise, not ownership.
   - `COMPLEX` with `affected_files` → most recent **active human** `TeamMember` who committed to those files in the last 12 months (`git log`, matched via `github_username`, `email` or `git_commit_emails`; authors matching `*[bot]`, `dependabot`, `renovate`, `github-actions` skipped).
   - Fallback → `project.owner`.
4. No resolvable owner, or the owner has no `slack_user_id` → finding is **unassigned**: Ampel red, posted to the team channel at T+0.

### 6.4 Live Verification
Runs after every agent report and after every scan.

**Application / container-image findings** (`PR_MERGED_WAITING_LIVE`) become `VERIFIED_LIVE` only when:
1. at least **one** running container is linked to the repository (for image findings: to the affected image repository), **and**
2. every linked container's host has `last_seen_at > pr_merged_at`, **and**
3. every linked container satisfies **one** of:
   - **(a) Revision proof:** the merge commit equals `oci_revision` or is an ancestor of it (GitHub compare `merge_commit_sha...oci_revision` returns `identical` or `ahead`);
   - **(b) Checkout proof** (`deployment_mode = HOST_CHECKOUT`): the merge commit equals `git_head_sha` or is an ancestor of it;
   - **(c) Scan proof:** the image scan of the running digest no longer reports any CVE of the cluster for `package_name`.

`image_created_at > pr_merged_at` is shown as a hint in the verification table but is **never** sufficient alone: a build of a pre-merge commit can finish after the merge, and reproducible builds report fixed timestamps.

If no container is linked and `deployment_mode = UNKNOWN`, the finding stays in `PR_MERGED_WAITING_LIVE` and the detail panel asks for a decision.

**Infrastructure findings** (`IN_PROGRESS`):
- apt security: `VERIFIED_LIVE` when the installed version ≥ fixed version for every affected package, `apt_lists_updated_at` is less than 26 h old, and `reboot_required == False` (kernel/libc updates are only live after reboot).
- Reboot: `reboot_required == False` reported after `acknowledged_at`.
- OS EOL: `os_version` changes to a supported release.

### 6.5 Dismissal & Snooze
- Mandatory `dismissal_reason` (min. 15 characters) and a mode: `SNOOZED` (14 or 30 days) or `DISMISSED`.
- `DISMISSED` mutes the key `(project, vulnerability_id, package_name)`; re-opens automatically when severity rises, the CVE becomes KEV-listed, or after 180 days.
- **Transparency rule (D-3):** for `HIGH` and `CRITICAL`, the dismissal/snooze takes effect immediately and the Slack bot posts to the team channel: *„ℹ️ @Moritz hat CVE-2026-xxxx in Projekt Würth als nicht betroffen markiert: ‚…‘“* with a button „Wieder öffnen“ that any team member can use (logged). This is a transparency rule, not a second-person approval.
- The actor is always the authenticated user (web session or verified Slack user), never a request field.

### 6.6 Notifications (Slack only)
- **One aggregated DM per assignee per scan run** listing new findings, each with buttons „Ich bin dran“ / „Details“. Unassigned findings → team channel.
- **Escalation:** when a deadline passes, post once to the team channel for that stage (`escalated_stage` prevents repeats) and mention the assignee. Escalations are only posted Mon–Fri 08:00–18:00 Europe/Berlin on working days; expiries outside that window post at the next window start. Exception: KEV-listed `CRITICAL` findings escalate immediately **(D-2)**.
- **Delivery log:** `NotificationLog(finding | null, kind, stage, recipient, slack_ts, sent_at)` with a unique constraint on `(finding, kind, stage, recipient)` → idempotent retries.
- Slack API failure: retried with backoff; persistent failure is shown in the dashboard health area and counts toward **Grau**.

### 6.7 Status-Ampel Rules (evaluated in order)
1. **GRAU – „Datenlage unvollständig“** if any of: last successful `ScanRun` older than 26 h; latest run `FAILED`, or `PARTIAL` with failed targets of monitored projects; any monitored host's agent stale > 60 min; Slack delivery failing. The banner lists the cause; findings are still shown.
2. **ROT – „Handlungsbedarf“** if any open finding is `NEW`, unassigned, or past its deadline.
3. **GELB – „In Bearbeitung“** if open findings exist and all are acknowledged and within deadline.
4. **GRÜN – „Alles im grünen Bereich“** otherwise.

---

## 7. Security Model

### 7.1 Web Authentication & Authorization
- OIDC authorization code flow with PKCE (`S256`) and confidential client secret; `state` and `nonce` verified.
- ID token validated: signature against the tenant JWKS, `iss == https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/v2.0`, `aud == MICROSOFT_CLIENT_ID`, `tid == MICROSOFT_TENANT_ID`, `exp`/`nbf`. `MICROSOFT_TENANT_ID` must be a GUID; `common`/`organizations`/`consumers` are rejected at startup.
- Binding: the first login matches `TeamMember.email` (case-insensitive, `@westcode.de`) and stores `oid`; later logins match on `oid` only. Logins without a matching active `TeamMember` are refused.
- Django sessions (cookie `Secure`, `HttpOnly`, `SameSite=Lax`, 12 h lifetime), CSRF protection for all unsafe methods (Angular XSRF header).
- DRF defaults: `SessionAuthentication` + `IsAuthenticated`. Admin-only endpoints: team management, project assignment, monitoring toggle, agent token generation.
- Endpoints exempt from session auth, each with its own authentication: `POST /api/agent/report/` (agent token), `POST /api/webhooks/slack/interactions/` (Slack signature), `POST /api/webhooks/github/` (GitHub signature), `GET /api/health/` (no data), OIDC login/callback. Webhook endpoints are CSRF-exempt and accept no session cookies.
- Local dev bypass only when `DEBUG=True` **and** `PATCHBOT_DEV_LOGIN=1`; the app refuses to start if the bypass is set while `DEBUG=False`.

### 7.2 Host Agent
- Push-only: the agent sends one report per run and ignores the response body. No job polling, no command execution paths. A unit test asserts that every subprocess invocation matches a read-only allowlist: `uname -r`, reading `/etc/os-release`, `dpkg-query -W`, `apt-get -s dist-upgrade`, `docker ps`, `docker inspect`, `docker image inspect`, `git -c safe.directory=<dir> rev-parse HEAD`, `git -c safe.directory=<dir> status --porcelain`.
- The server derives the host from the bearer token (hashed per host) and ignores the `hostname` field for identity; token rotation via `/api/hosts/<slug>/token/` (admin).
- systemd unit: `Type=oneshot`, no `Restart=`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, `ReadOnlyPaths=/opt`. Validate on a staging VM that `apt-get -s` and `docker inspect` work under these restrictions before fleet rollout.
- Residual risk (accepted for the initial rollout, **D-4**): the agent runs as root with Docker socket access. Acceptable because it executes no server-supplied input. A read-only Docker socket proxy is re-evaluated after the agent runs on all 23 VMs.

### 7.3 Public Webhooks (D-1)
- **Slack interactivity:** every request verified with `SLACK_SIGNING_SECRET` — HMAC-SHA256 over `v0:{X-Slack-Request-Timestamp}:{raw body}`, constant-time compare against `X-Slack-Signature`, timestamp ≤ 5 min old; otherwise `401`.
- **GitHub:** every delivery verified with `GITHUB_WEBHOOK_SECRET` via `X-Hub-Signature-256` (HMAC-SHA256 over the raw body, constant-time compare); deliveries deduplicated by `X-GitHub-Delivery`; only events for installed `westcoder` repositories are processed.
- Slack user → `TeamMember` via `slack_user_id`; actions from unknown Slack users are rejected.
- Webhook payloads are untrusted: handlers only enqueue an event; the worker re-reads PR state from the GitHub API before changing a finding.
- Security tests: missing/invalid signature → `401`; replayed Slack timestamp → `401`; duplicate GitHub delivery → no second state change.

### 7.4 GitHub & LLM
- GitHub App with minimal permissions (§3.2); an org ruleset allows the app to push only to `patchbot/*`; no access to `westcode-infra` (D-5).
- Untrusted text (advisories, changelogs, PR bodies, repository code) is never interpreted as instructions; Claude's output is parsed against the schema and never executed.
- Sandbox and diff gate as in §5.5.

### 7.5 Secrets
All credentials come from the environment/secret store, never from the repository or the database; agent tokens are stored hashed.

---

## 8. Frontend (`frontend/`)

1. **Top navigation:** Westcode wordmark + signet (`westcode-schwarz.svg`); tabs:
   1. **Triage-Dashboard** (`/`) — sub-switch **„Sicherheits-Triage“** / **„Wartungs-Updates (ohne CVE)“** / **„Automatisch gefiltert“**
   2. **Projekte & Zuordnung** (`/projects`) — Notion sync, `is_monitored` toggle, „Unzugeordnete Assets“ inbox, `deployment_mode` per repository, Projekt ↔ Repo ↔ Container ↔ Host editor
   3. **Live-Hosts** (`/hosts`, count rendered dynamically) — telemetry freshness, kernel, reboot flag, packages, containers (digest, `oci_revision`, `image_created_at`, `/opt` Git state), manual runbooks, agent token generator (admin)
   4. **Team** (`/team`) — `TeamMember` directory (email ↔ GitHub ↔ Slack ↔ layers ↔ admin/infra owner), Slack test DM
   - Right side: logged-in user badge, **„Scan & Sync starten“** (disabled while a scan runs, shows progress).
2. **Triage-Dashboard:**
   - **Status-Ampel banner** with the four states of §6.7; GRAU lists its causes.
   - **Filter bar:** grouping „Nach Aufwand“ / „Nach Projekt“; filter „Nur meine Aufgaben“; severity filter.
   - **Master-detail:** left buckets **1. Einfache Fixes**, **2. Komplexe Eingriffe**, **3. Gemergt – Wartet auf Live-Gang**; right sticky detail panel (45° cut) with Claude assessment + confidence + policy-gate result, affected files, assignee and deadline countdown, „Ich bin dran“, „Snooze / Nicht betroffen“ modal (mandatory reason), extend-deadline action, PR badge (draft/ready/bot, CI status), live verification table per container (proof a/b/c; `Image gebaut am` vs. `PR gemergt am` as hint), and the `FindingEvent` history.

---

## 9. Migration from v1

1. Remove the agent job channel (`AgentJob` model, `/api/agent/jobs/*` endpoints, `dispatch_agent_job`, `compose_update`/`apt_upgrade`/`host_reboot` code paths) and the `rollouts` orchestrator including `_default_github_merger`; drop their tests.
2. Remove the Zammad/email transports from `alerts`; `NotificationLog` replaces `AlertFingerprint`.
3. Remove synthetic `HostContainer` creation and the hard-coded local projects path from `catalog/live_sync.py`; delete existing synthetic container rows.
4. Replace `catalog.VulnerabilityFinding`/`ServiceGroup` with v2 `Finding` data; the first v2 scan rebuilds state (no data migration of v1 findings).
5. Roll out the new agent to all 23 VMs before enabling live verification; hosts on the old agent count as stale (→ GRAU).
6. Ask project CIs to set the OCI labels `org.opencontainers.image.revision` and `org.opencontainers.image.source` (default in `docker/metadata-action`); containers without them fall back to scan proof (c).

---

## 10. Decisions (resolved 2026-11-05)

| ID | Question | Decision | Consequence |
|---|---|---|---|
| **D-1** | Public ingress for Slack interactivity / GitHub webhooks? | **Public webhook endpoints** | Only the two webhook paths are public (§3.3); signature verification + replay/dedupe protection (§7.3); hourly PR reconciliation poll as fallback. |
| **D-2** | Grace periods in wall-clock hours or working days? | **Working days + KEV exception** | 1/2/5/1 working days (Mon–Fri, Europe/Berlin, holiday list); escalation posts 08:00–18:00; `CRITICAL` + KEV in wall-clock hours with immediate escalation (§6.2, §6.6). |
| **D-3** | Second-person approval for dismissing HIGH/CRITICAL? | **Transparency post only** | Dismissal takes effect immediately; team-channel post with „Wieder öffnen“ button; named „transparency rule“, not „four-eyes“ (§6.5). |
| **D-4** | Read-only Docker socket proxy on every VM? | **Later** | Root + Docker socket accepted as documented residual risk for the initial rollout; re-evaluated after full agent rollout (§7.2). |
| **D-5** | Draft-PRs in `westcode-infra` for OS EOL migrations? | **Runbook checklist only** | EOL finding with migration checklist; GitHub App has no access to `westcode-infra` (§5.5). |

---

## Appendix A — Refinement Log (v2.0 → v2.1)

| Section | Change | Reason |
|---|---|---|
| §1 Intent | Added problems 4 (silent failures, synthetic data) and 5 (unscanned images) | Found in v1 code: `scan_local_repo_with_trivy` swallows errors, `run_live_sync` fabricates containers, local path hard-coded |
| §2 Goals | Ampel state **Grau**; anti-goals: no auto-merge, no AI-only suppression of CRITICAL/KEV, no false green, aggregated DMs; success criteria | Close gaps that would undermine trust in the dashboard |
| §3 Constraints | Model `claude-sonnet-5-5`; Trivy as single scanner + KEV/EPSS; GitHub App instead of token; ECR read role; public webhook paths only (D-1); runtime topology & scheduler | v2.0 named sources without an ingestion path and had no scheduler/worker |
| §4 Inventory/Fleet | `entra_object_id`, `is_admin`; Notion precedence rules; `deployment_mode`; auto-match signals; installed package list, `apt_lists_updated_at`, `oci_source`; no synthetic containers | Email is not a stable identity; avoid vacuous "verified"; stale apt lists are not proof |
| §5 Research | ScanRun/TargetScan health; image-layer scanning; cluster key & dedupe; deterministic policy gate around Claude; PR principles; sandbox & diff gate; no pushes to bot branches | Prevent duplicate findings, silent AI suppression, prompt injection with write access |
| §6 Triage | State table incl. `RESOLVED_NO_DEPLOYMENT`, `SUPPRESSED_UNMONITORED`; ownership by layer/complexity; verification fixed (merge commit must be an **ancestor of** the running revision/HEAD; ≥ 1 container; fresh telemetry); `image_created_at` demoted to hint; idempotent notifications; audit log; PR merge polling | v2.0 had the ancestry direction reversed and allowed verification with zero containers |
| §7 Security | New section: OIDC validation, `oid` binding, sessions/CSRF/permissions, push-only agent allowlist, oneshot unit, Slack + GitHub webhook signature verification, secrets | v2.0 had no authorization model and no webhook request verification |
| §5.5 / §6.2 | Claude loop runs in `worker`, sandbox gets no API key and registry-only egress; KEV wall-clock deadlines spelled out per stage | Clarified while writing the implementation plan |
| §6 / §10 | Decisions D-1…D-5: public webhooks, working-day deadlines with KEV exception, transparency-only dismissal, Docker proxy deferred, EOL runbook only | Resolved with the user on 2026-11-05 |
| §8 Frontend | „Automatisch gefiltert“ tab, GRAU banner, extend action, event history; „Team & Schichten“ → „Team“ (no shift model exists) | Align UI with lifecycle |
| §9 Migration | New: v1 decommission steps | v1 mutating paths conflict with the anti-goals |
