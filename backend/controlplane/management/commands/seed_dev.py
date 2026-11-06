"""Demo data for local development (DEBUG only). Idempotent: re-running refreshes timestamps.

Covers every UI surface: findings in all states and layers, projects (monitored / unmonitored /
unassigned suggestions), hosts with packages and containers, maintenance PRs, a finished scan run
and healthy integrations. Agents count as fresh for 60 minutes, so re-run the command when the
Ampel turns grey ("Agent ... stumm").
"""

from datetime import date, timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from fleet.models import Host, HostContainer, HostPackage
from inventory.models import Project, RepositoryAsset, TeamMember
from research.models import ExploitSignal, MaintenanceUpdate, ScanRun, TargetScan
from triage.models import Finding, FindingEvent, IntegrationHealth

OS_EOL_RUNBOOK = """Checkliste OS-Migration (Ubuntu 20.04 → 24.04)
1. Neues Image mit Ubuntu 24.04 bauen (servers.tf / Packer) und VM daneben hochziehen.
2. Daten migrieren (Volumes, Datenbank-Dump, .env, Zertifikate).
3. Smoke-Test auf der neuen VM, dann DNS umstellen.
4. Alte VM 7 Tage stoppen, danach löschen und aus servers.tf entfernen.
5. Agent auf der neuen VM installieren und Token neu erzeugen."""


class Command(BaseCommand):
    help = "Create demo data for local development. Refuses to run unless DEBUG is on."

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError("seed_dev only runs with DJANGO_DEBUG=true (never in production).")
        self.now = timezone.now()
        members = self._team()
        projects = self._projects(members)
        repos = self._repos(projects)
        hosts = self._hosts(projects, repos)
        self._signals()
        self._findings(members, projects, repos, hosts)
        self._maintenance(repos)
        self._scan_run(repos, hosts)
        for name in ("slack", "github", "notion", "anthropic", "trivy"):
            IntegrationHealth.objects.update_or_create(name=name, defaults={"ok": True, "last_error": "",
                                                                            "checked_at": self.now})
        self.stdout.write(self.style.SUCCESS(
            f"Demo-Daten angelegt: {Finding.objects.count()} Findings, {Project.objects.count()} Projekte, "
            f"{Host.objects.count()} Hosts. Login als dev@westcode.de (PATCHBOT_DEV_LOGIN=1)."))

    # --- team / projects / assets ------------------------------------------------------------------
    def _team(self) -> dict[str, TeamMember]:
        rows = [
            ("dev", "Dev User", {"is_admin": True, "is_default_infra_owner": True, "slack_user_id": "UDEV",
                                 "layers": ["APPLICATION", "CONTAINER_IMAGE", "INFRASTRUCTURE"],
                                 "github_username": "dev-westcode"}),
            ("anna", "Anna Schmidt", {"slack_user_id": "UANNA", "layers": ["APPLICATION"],
                                      "github_username": "anna-ws",
                                      "git_commit_emails": ["anna@users.noreply.github.com"]}),
            ("ben", "Ben Weber", {"slack_user_id": "UBEN", "layers": ["INFRASTRUCTURE", "CONTAINER_IMAGE"],
                                  "github_username": "ben-ws"}),
            ("clara", "Clara Hoffmann", {"slack_user_id": "UCLARA", "layers": ["APPLICATION"]}),
            ("tim", "Tim Ehemalig", {"is_active": False}),
        ]
        members = {}
        for key, name, extra in rows:
            members[key], _ = TeamMember.objects.update_or_create(
                email=f"{key}@westcode.de", defaults={"name": name, **extra})
        return members

    def _projects(self, m) -> dict[str, Project]:
        rows = [
            ("kundenportal", "Kundenportal", "Muster Versicherung AG", False, "In progress", m["anna"], True),
            ("shop", "Shop-Relaunch", "Beispiel Handel GmbH", False, "In maintenance", m["clara"], True),
            ("intranet", "Westcode Intranet", "", True, "In maintenance", m["dev"], True),
            ("altprojekt", "Altprojekt Messe 2024", "Messe Demo e.V.", False, "Done", m["clara"], False),
        ]
        projects = {}
        for slug, name, customer, internal, status, owner, monitored in rows:
            projects[slug], _ = Project.objects.update_or_create(slug=slug, defaults={
                "name": name, "customer_name": customer, "is_internal": internal, "notion_status": status,
                "owner": owner, "is_monitored": monitored, "notion_page_id": f"demo-{slug}",
                "last_notion_synced_at": self.now - timedelta(hours=2)})
        # Project from the old seed: keep it, but out of the way.
        Project.objects.filter(slug="demo").update(is_monitored=False, notion_status="Done")
        return projects

    def _repos(self, p) -> dict[str, RepositoryAsset]:
        rows = [
            ("kundenportal-api", p["kundenportal"], None, "CONTAINER", True),
            ("kundenportal-web", p["kundenportal"], None, "CONTAINER", True),
            ("shop-backend", p["shop"], None, "HOST_CHECKOUT", False),
            ("intranet", p["intranet"], None, "CONTAINER", True),
            ("messe-landingpage", p["altprojekt"], None, "NONE", False),
            ("shop-admin-tools", None, p["shop"], "UNKNOWN", False),  # unassigned, with a suggestion
        ]
        repos = {}
        for name, project, suggested, mode, bot in rows:
            repos[name], _ = RepositoryAsset.objects.update_or_create(full_name=f"westcoder/{name}", defaults={
                "project": project, "suggested_project": suggested, "deployment_mode": mode,
                "has_bot_updates": bot, "last_scanned_at": self.now - timedelta(hours=3),
                "last_scanned_commit_sha": "3f9c2e1a7b" + "0" * 30})
        return repos

    def _hosts(self, p, r) -> dict[str, Host]:
        rows = [
            ("kundenportal-prod-01", p["kundenportal"], None, "ubuntu", "24.04", date(2029, 5, 31), False, "6.8.0-48"),
            ("shop-prod-01", p["shop"], None, "ubuntu", "20.04", date(2025, 5, 31), True, "5.4.0-200"),
            ("shared-docker-01", None, p["intranet"], "debian", "12", date(2028, 6, 30), False, "6.1.0-26"),
        ]
        hosts = {}
        for slug, project, suggested, distro, version, eol, reboot, kernel in rows:
            hosts[slug], _ = Host.objects.update_or_create(slug=slug, defaults={
                "hostname": f"{slug}.westcode.de", "provider": "hetzner", "stack_name": f"hetzner-{slug}",
                "project": project, "suggested_project": suggested, "os_distro": distro, "os_version": version,
                "os_eol_date": eol, "is_os_eol": eol < self.now.date(), "kernel_version": kernel,
                "reboot_required": reboot, "apt_lists_updated_at": self.now - timedelta(hours=5),
                "agent_version": "2.0.0", "last_seen_at": self.now - timedelta(minutes=4)})

        packages = {
            "kundenportal-prod-01": [("openssl", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", True),
                                     ("curl", "8.5.0-2ubuntu10.4", "8.5.0-2ubuntu10.6", True),
                                     ("vim", "2:9.1.0016-1ubuntu7.3", "", False)],
            "shop-prod-01": [("openssh-server", "1:8.2p1-4ubuntu0.11", "1:8.2p1-4ubuntu0.13", True),
                             ("libc6", "2.31-0ubuntu9.16", "2.31-0ubuntu9.17", True),
                             ("nginx", "1.18.0-0ubuntu1.5", "", False)],
            "shared-docker-01": [("docker-ce", "5:27.3.1-1~debian.12~bookworm", "", False)],
        }
        for slug, pkgs in packages.items():
            for name, installed, candidate, security in pkgs:
                HostPackage.objects.update_or_create(host=hosts[slug], name=name, defaults={
                    "installed_version": installed, "candidate_version": candidate, "is_security_update": security,
                    "source_pocket": "security" if security else ""})

        containers = [
            ("kundenportal-prod-01", "kundenportal-api", "ghcr.io/westcoder/kundenportal-api:2026.11.03",
             p["kundenportal"], r["kundenportal-api"], "a1b2c3d"),
            ("kundenportal-prod-01", "kundenportal-web", "ghcr.io/westcoder/kundenportal-web:2026.10.28",
             p["kundenportal"], r["kundenportal-web"], "d4e5f6a"),
            ("shared-docker-01", "intranet", "ghcr.io/westcoder/intranet:latest",
             p["intranet"], r["intranet"], "0badc0d"),
            ("shared-docker-01", "redis", "redis:7.2-alpine", None, None, ""),  # unassigned
        ]
        for host_slug, name, image, project, repo, rev in containers:
            HostContainer.objects.update_or_create(host=hosts[host_slug], name=name, defaults={
                "container_id": f"{name[:6]}0123456789", "image_tag": image, "image_id": f"sha256:{name:0<12}",
                "oci_revision": rev, "oci_source": f"https://github.com/{repo.full_name}" if repo else "",
                "image_created_at": self.now - timedelta(days=3), "compose_service": name,
                "working_dir": f"/opt/{name}", "status": "running", "reported_at": self.now - timedelta(minutes=4),
                "project": project, "repository": repo})
        return hosts

    def _signals(self):
        for cve, kev, epss in [("CVE-2026-31337", True, 0.94), ("CVE-2026-28810", False, 0.31),
                               ("CVE-2026-40021", False, 0.02), ("CVE-2026-19555", True, 0.71)]:
            ExploitSignal.objects.update_or_create(cve_id=cve, defaults={
                "kev_listed": kev, "kev_added_at": date(2026, 10, 20) if kev else None, "epss": epss,
                "updated_at": self.now})

    # --- findings ----------------------------------------------------------------------------------
    def _findings(self, m, p, r, h):
        now, day = self.now, timedelta(days=1)
        api, web, shop, intra = r["kundenportal-api"], r["kundenportal-web"], r["shop-backend"], r["intranet"]
        app = {"layer": "APPLICATION"}
        rows = [
            # NEW, CRITICAL + KEV, calendar deadline
            dict(app, project=p["kundenportal"], repository=api, ecosystem="npm", package_name="express",
                 current_version="4.19.2", target_version="4.21.3", vulnerability_ids=["CVE-2026-31337"],
                 highest_severity="CRITICAL", kev_listed=True, max_epss=0.94, state="NEW", assignee=m["anna"],
                 assigned_reason_de="Letzte Änderungen an package.json", complexity="SIMPLE",
                 reachability="REACHABLE", confidence=0.9, deadline_at=now + timedelta(hours=20),
                 discovered_at=now - timedelta(hours=4), affected_files=["src/server.ts", "src/routes/upload.ts"],
                 summary_de="Pfad-Traversal in express.static bei manipulierten URLs. Das Kundenportal liefert "
                            "Uploads über express.static aus – ausnutzbar ohne Login.",
                 breaking_changes_de="Keine – Patch-Release innerhalb 4.x."),
            # NEW, overdue, unassigned (forces RED)
            dict(app, project=p["shop"], repository=shop, ecosystem="pip", package_name="django",
                 current_version="4.2.11", target_version="4.2.17", vulnerability_ids=["CVE-2026-28810"],
                 highest_severity="HIGH", max_epss=0.31, state="NEW", assignee=None,
                 assigned_reason_de="Kein Owner ermittelbar", complexity="SIMPLE", reachability="LIKELY",
                 confidence=0.7, deadline_at=now - timedelta(hours=6), discovered_at=now - 4 * day,
                 affected_files=["shop/settings.py"],
                 summary_de="SQL-Injection über QuerySet.values() mit JSONField-Keys. Der Shop nutzt JSONField "
                            "in der Produktsuche.", breaking_changes_de="Keine."),
            # IN_PROGRESS with an open Patchbot PR (CI green)
            dict(app, project=p["kundenportal"], repository=web, ecosystem="npm", package_name="axios",
                 current_version="1.6.8", target_version="1.7.9", vulnerability_ids=["CVE-2026-40021"],
                 highest_severity="HIGH", max_epss=0.02, state="IN_PROGRESS", assignee=m["anna"],
                 acknowledged_at=now - 2 * day, complexity="SIMPLE", reachability="REACHABLE", confidence=0.8,
                 deadline_at=now + 3 * day, discovered_at=now - 3 * day, pr_number=412,
                 pr_url="https://github.com/westcoder/kundenportal-web/pull/412", pr_source="PATCHBOT",
                 pr_target_version="1.7.9", pr_head_ref="patchbot/axios-1.7.9", ci_status="success",
                 summary_de="SSRF über absolute URLs in baseURL-Requests.",
                 breaking_changes_de="1.7 ändert die Fetch-Adapter-Auswahl; Tests decken die API-Clients ab."),
            # IN_PROGRESS, COMPLEX, draft AI PR, CI failing
            dict(app, project=p["intranet"], repository=intra, ecosystem="npm", package_name="next",
                 current_version="14.1.0", target_version="14.2.25", vulnerability_ids=["CVE-2026-19555"],
                 highest_severity="CRITICAL", kev_listed=True, max_epss=0.71, state="IN_PROGRESS",
                 assignee=m["dev"], acknowledged_at=now - day, complexity="COMPLEX", reachability="REACHABLE",
                 confidence=0.6, deadline_at=now + timedelta(hours=30), discovered_at=now - day, pr_number=88,
                 pr_url="https://github.com/westcoder/intranet/pull/88", pr_is_draft=True, pr_source="PATCHBOT",
                 pr_target_version="14.2.25", pr_head_ref="patchbot/next-14.2.25", ci_status="failure",
                 affected_files=["middleware.ts", "app/api/auth/route.ts"],
                 summary_de="Authentifizierungs-Bypass in der Middleware über x-middleware-subrequest.",
                 breaking_changes_de="Middleware-Matcher-Syntax geändert; KI-Entwurf passt middleware.ts an, "
                                     "zwei Tests schlagen noch fehl."),
            # PR merged, waiting for live deployment
            dict(app, project=p["kundenportal"], repository=api, ecosystem="npm", package_name="jsonwebtoken",
                 current_version="9.0.0", target_version="9.0.2", vulnerability_ids=["CVE-2026-11873"],
                 highest_severity="MEDIUM", state="PR_MERGED_WAITING_LIVE", assignee=m["anna"],
                 acknowledged_at=now - 5 * day, complexity="SIMPLE", deadline_at=now + 6 * day,
                 discovered_at=now - 6 * day, pr_number=405,
                 pr_url="https://github.com/westcoder/kundenportal-api/pull/405",
                 pr_source="RENOVATE", pr_target_version="9.0.2", ci_status="success",
                 merge_commit_sha="9e8d7c6b5a" + "1" * 30, pr_merged_at=now - day,
                 summary_de="Schwache Algorithmus-Prüfung bei asymmetrischen Keys."),
            # Container image layer
            dict(layer="CONTAINER_IMAGE", project=p["kundenportal"], repository=api,
                 image_ref="ghcr.io/westcoder/kundenportal-api:2026.11.03", ecosystem="debian",
                 package_name="libssl3", current_version="3.0.15-1~deb12u1", target_version="3.0.16-1~deb12u1",
                 vulnerability_ids=["CVE-2026-20777"], highest_severity="HIGH", state="NEW", assignee=m["ben"],
                 assigned_reason_de="Infrastruktur-Owner", complexity="SIMPLE", deadline_at=now + 2 * day,
                 discovered_at=now - timedelta(hours=10),
                 summary_de="Base-Image veraltet; neuer Build mit aktuellem node:22-bookworm-slim behebt es."),
            # Infrastructure: OS EOL with manual runbook
            dict(layer="INFRASTRUCTURE", project=p["shop"], host=h["shop-prod-01"], ecosystem="ubuntu",
                 package_name="__os_eol__", current_version="20.04", target_version="24.04",
                 highest_severity="HIGH", state="IN_PROGRESS", assignee=m["ben"], acknowledged_at=now - 10 * day,
                 complexity="COMPLEX", deadline_at=now + 9 * day, discovered_at=now - 12 * day,
                 manual_runbook=OS_EOL_RUNBOOK,
                 summary_de="Ubuntu 20.04 ist seit 31.05.2025 ohne Standard-Support. Keine Sicherheitsupdates mehr."),
            # Infrastructure: OS package
            dict(layer="INFRASTRUCTURE", project=p["shop"], host=h["shop-prod-01"], ecosystem="ubuntu",
                 package_name="openssh-server", current_version="1:8.2p1-4ubuntu0.11",
                 target_version="1:8.2p1-4ubuntu0.13", vulnerability_ids=["CVE-2026-26465"],
                 highest_severity="MEDIUM", state="NEW", assignee=m["ben"], complexity="SIMPLE",
                 deadline_at=now + 8 * day, discovered_at=now - timedelta(hours=7),
                 summary_de="apt upgrade openssh-server genügt; Neustart von sshd nötig."),
            # Parked / terminal states
            dict(app, project=p["shop"], repository=shop, ecosystem="pip", package_name="pillow",
                 current_version="10.2.0", target_version="10.3.0", vulnerability_ids=["CVE-2026-10101"],
                 highest_severity="MEDIUM", state="SNOOZED", assignee=m["clara"], dismissal_mode="SNOOZED",
                 dismissal_reason="Warten auf Release-Freeze-Ende am Montag.", dismissed_by=m["clara"],
                 dismissed_at=now - day, snoozed_until=now + 4 * day, discovered_at=now - 2 * day),
            dict(app, project=p["kundenportal"], repository=web, ecosystem="npm", package_name="semver",
                 current_version="7.5.1", target_version="7.5.2", vulnerability_ids=["CVE-2026-25883"],
                 highest_severity="HIGH", state="DISMISSED", dismissal_mode="DISMISSED",
                 dismissal_reason="Nur in Build-Tooling (devDependency), nicht im ausgelieferten Bundle.",
                 dismissed_by=m["anna"], dismissed_at=now - 3 * day, dismissed_severity="HIGH",
                 discovered_at=now - 5 * day),
            dict(app, project=p["intranet"], repository=intra, ecosystem="npm", package_name="debug",
                 current_version="2.6.8", target_version="2.6.9", vulnerability_ids=["CVE-2026-20165"],
                 highest_severity="LOW", state="FILTERED_IRRELEVANT", reachability="NOT_REACHABLE",
                 discovered_at=now - 2 * day,
                 summary_de="ReDoS nur bei untrusted Namespace-Strings; im Intranet nicht erreichbar."),
            dict(app, project=p["altprojekt"], repository=r["messe-landingpage"], ecosystem="npm",
                 package_name="vite", current_version="5.0.0", target_version="5.0.13",
                 vulnerability_ids=["CVE-2026-31125"], highest_severity="HIGH", state="SUPPRESSED_UNMONITORED",
                 discovered_at=now - 9 * day),
            dict(app, project=p["kundenportal"], repository=api, ecosystem="npm", package_name="body-parser",
                 current_version="1.20.2", target_version="1.20.3", vulnerability_ids=["CVE-2026-45590"],
                 highest_severity="HIGH", state="VERIFIED_LIVE", assignee=m["anna"],
                 acknowledged_at=now - 9 * day, verified_live_at=now - 2 * day, discovered_at=now - 10 * day,
                 pr_number=398, pr_url="https://github.com/westcoder/kundenportal-api/pull/398",
                 pr_source="PATCHBOT", merge_commit_sha="77aa55" + "2" * 34, pr_merged_at=now - 4 * day,
                 verification_checked_at=now - 2 * day, summary_de="DoS über URL-encoded Bodies."),
            dict(app, project=p["altprojekt"], repository=r["messe-landingpage"], ecosystem="npm",
                 package_name="postcss", current_version="8.4.20", target_version="8.4.31",
                 vulnerability_ids=["CVE-2026-44270"], highest_severity="MEDIUM",
                 state="RESOLVED_NO_DEPLOYMENT", discovered_at=now - 20 * day, pr_number=12,
                 pr_url="https://github.com/westcoder/messe-landingpage/pull/12", pr_merged_at=now - 15 * day),
        ]
        for row in rows:
            row.setdefault("triage_status", "TRIAGED")
            if row.get("image_ref"):
                target_ref = f"image:{row['image_ref']}"
            elif row.get("host"):
                target_ref = f"host:{row['host'].slug}"
            else:
                target_ref = f"repo:{row['repository'].full_name}"
            key = {k: row.pop(k) for k in ("project", "layer", "ecosystem", "package_name")}
            finding, _ = Finding.objects.update_or_create(target_ref=target_ref, **key, defaults=row)
            if not finding.events.exists():
                self._history(finding)

    def _history(self, f: Finding):
        events = [(f.discovered_at, None, "SYSTEM", "", "NEW", "Durch Scan entdeckt.")]
        if f.acknowledged_at:
            events.append((f.acknowledged_at, f.assignee, "SLACK", "NEW", "IN_PROGRESS", "„Ich bin dran“ geklickt."))
        if f.pr_number and f.pr_source == "PATCHBOT":
            events.append(((f.acknowledged_at or f.discovered_at) + timedelta(hours=1), None, "SYSTEM", "", "",
                           f"Patchbot-PR #{f.pr_number} erstellt."))
        if f.pr_merged_at:
            events.append((f.pr_merged_at, None, "GITHUB", "IN_PROGRESS", "PR_MERGED_WAITING_LIVE",
                           f"PR #{f.pr_number} gemergt."))
        if f.state == "VERIFIED_LIVE":
            events.append((f.verified_live_at, None, "SYSTEM", "PR_MERGED_WAITING_LIVE", "VERIFIED_LIVE",
                           "Fix live nachgewiesen (Container-Revision enthält Merge-Commit)."))
        if f.state in ("SNOOZED", "DISMISSED"):
            events.append((f.dismissed_at, f.dismissed_by, "WEB", "NEW", f.state, f.dismissal_reason))
        if f.state == "FILTERED_IRRELEVANT":
            events.append((f.discovered_at + timedelta(minutes=2), None, "SYSTEM", "NEW", f.state,
                           "Policy-Gate: LOW, nicht erreichbar, kein KEV, EPSS < 0,10."))
        for at, actor, source, from_state, to_state, note in events:
            FindingEvent.objects.create(finding=f, at=at, actor=actor, source=source, from_state=from_state,
                                        to_state=to_state, note=note)

    # --- maintenance / scans -----------------------------------------------------------------------
    def _maintenance(self, r):
        for repo, package, cur, tgt, kind, pr, ci in [
            ("kundenportal-web", "@angular/core", "20.3.1", "20.3.4", "PATCH", 415, "success"),
            ("kundenportal-api", "typescript", "5.6.3", "5.8.2", "MINOR", 409, "pending"),
            ("intranet", "eslint", "8.57.0", "9.17.0", "MAJOR", 91, "failure"),
        ]:
            asset = r[repo]
            MaintenanceUpdate.objects.update_or_create(repository=asset, package_name=package, defaults={
                "project": asset.project, "current_version": cur, "target_version": tgt, "update_type": kind,
                "pr_number": pr, "pr_url": f"https://github.com/{asset.full_name}/pull/{pr}", "ci_status": ci,
                "summary_de": f"Renovate: {package} {cur} → {tgt}."})

    def _scan_run(self, r, h):
        if ScanRun.objects.filter(status="OK", finished_at__gte=self.now - timedelta(hours=20)).exists():
            return
        started = self.now - timedelta(hours=3)
        run = ScanRun.objects.create(trigger="SCHEDULED", status="OK", started_at=started,
                                     finished_at=started + timedelta(minutes=14))
        for repo in r.values():
            TargetScan.objects.create(scan_run=run, target_type="REPO", target_ref=f"repo:{repo.full_name}",
                                      status="OK", vulnerability_count=3, duration_ms=18_000)
        for host in h.values():
            TargetScan.objects.create(scan_run=run, target_type="HOST", target_ref=f"host:{host.slug}",
                                      status="OK", vulnerability_count=2, duration_ms=900)
