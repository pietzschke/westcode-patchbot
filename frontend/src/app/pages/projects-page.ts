import { Component, OnInit, computed, effect, inject, signal } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { getLogoSvg } from '../core/logos';
import { GitTargetDto, PatchbotApi, ProjectDto } from '../core/patchbot-api';

@Component({
  selector: 'app-projects-page',
  standalone: true,
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1 class="page-title">Nach Projekt ({{ projects().length || 17 }})</h1>
          <p class="page-sub">
            Bündelt zusammengehörige Hosts, Dienste, Container und GitHub-Repositories je Kunden- bzw.
            Infrastruktur-Projekt (z.&nbsp;B. <strong>Würth</strong> mit <code>mdb.westcode.de</code>,
            <code>converter.westcode.de</code>, Materialdatenbank und Würth Converter).
          </p>
        </div>
      </div>

      <div class="workspace">
        <div>
          <section class="group-section" aria-label="Jetzt handeln">
            <div class="group-head">
              <span>Jetzt handeln · Projekte mit offenen CVEs, EOL-Systemen oder Updates</span>
              <span class="group-count">{{ actionRequiredProjects().length }} Projekte</span>
            </div>

            <ul class="service-list" role="listbox" aria-label="Dringende Projekte">
              @for (proj of actionRequiredProjects(); track proj.slug) {
                <li
                  class="service-row"
                  role="option"
                  [class.selected]="selectedProject()?.slug === proj.slug"
                  [attr.aria-selected]="selectedProject()?.slug === proj.slug"
                  (click)="selectProject(proj)"
                >
                  <div
                    class="svc-logo"
                    [innerHTML]="renderLogo(proj.logo_key, proj.display_name)"
                  ></div>
                  <div class="svc-main">
                    <div class="svc-title">
                      {{ proj.display_name }}
                      @if (proj.has_eol_host) {
                        <span class="badge-eol" style="margin-left:6px;">EOL</span>
                      }
                      @if (proj.has_git_dirty) {
                        <span class="badge-eol" style="margin-left:6px;background:#fff7ed;color:#c2410c;">git dirty</span>
                      }
                    </div>
                    <div class="svc-sub">
                      @if (proj.cves_count > 0) {
                        <span class="crit-text">{{ proj.cves_count }} CVEs</span> ·
                      }
                      {{ proj.summary_line }}
                    </div>
                  </div>
                  <div class="svc-version">
                    <span class="old">{{ proj.hosts.length }} {{ proj.hosts.length === 1 ? 'Host' : 'Hosts' }}</span>
                    →
                    <span class="new">{{ proj.services.length }} {{ proj.services.length === 1 ? 'Dienst' : 'Dienste' }}</span>
                  </div>
                  <div class="svc-scope">
                    <span class="dot crit"></span>
                    <span>{{ proj.prs_count }} PRs · {{ proj.pending_apt_count }} APT</span>
                  </div>
                  <div class="svc-chevron">›</div>
                </li>
              }
            </ul>
          </section>

          <section class="group-section" aria-label="Weitere Projekte">
            <div class="group-head">
              <span>Bereit zum Ausrollen / Infrastruktur-Stacks</span>
              <span class="group-count">{{ readyProjects().length }} Projekte</span>
            </div>

            <ul class="service-list" role="listbox" aria-label="Weitere Projekte">
              @for (proj of readyProjects(); track proj.slug) {
                <li
                  class="service-row"
                  role="option"
                  [class.selected]="selectedProject()?.slug === proj.slug"
                  [attr.aria-selected]="selectedProject()?.slug === proj.slug"
                  (click)="selectProject(proj)"
                >
                  <div
                    class="svc-logo"
                    [innerHTML]="renderLogo(proj.logo_key, proj.display_name)"
                  ></div>
                  <div class="svc-main">
                    <div class="svc-title">{{ proj.display_name }}</div>
                    <div class="svc-sub">{{ proj.summary_line }}</div>
                  </div>
                  <div class="svc-version">
                    <span class="old">{{ proj.hosts.length }} {{ proj.hosts.length === 1 ? 'Host' : 'Hosts' }}</span>
                    →
                    <span class="new">{{ proj.services.length }} {{ proj.services.length === 1 ? 'Dienst' : 'Dienste' }}</span>
                  </div>
                  <div class="svc-scope">
                    <span class="dot hint"></span>
                    <span>{{ proj.prs_count }} PRs · {{ proj.pending_apt_count }} APT</span>
                  </div>
                  <div class="svc-chevron">›</div>
                </li>
              }
            </ul>
          </section>
        </div>

        @if (selectedProject(); as proj) {
          <aside
            class="plan-stripe-wrap plan-card"
            [class.crit]="proj.category === 'action_required'"
            aria-label="Projekt-Details und Runbook"
          >
            <div class="plan-panel">
              <div class="plan-header">
                <div
                  class="svc-logo"
                  style="background:#fff;"
                  [innerHTML]="renderLogo(proj.logo_key, proj.display_name)"
                ></div>
                <div>
                  <h2 class="plan-title">{{ proj.display_name }}</h2>
                  <div class="plan-meta">
                    Stack: <code>{{ proj.slug }}</code> · {{ proj.hosts.length }} Hosts ·
                    {{ proj.services.length }} Dienste
                    @if (proj.cves_count > 0) {
                      · <strong style="color:var(--salmon-700);">{{ proj.cves_count }} CVEs</strong>
                    }
                  </div>
                </div>
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>1. Zugehörige Hosts im Projekt</span>
                  <span>{{ proj.hosts.length }} Hosts</span>
                </div>
                @for (h of proj.hosts; track h.hostname) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ h.hostname }}</strong>
                      @if (h.is_os_eol || h.is_eol) {
                        <span class="badge-eol" style="margin-left:6px;">EOL</span>
                      }
                      <span class="plan-item-sub" style="display:block;">
                        {{ h.distro || (h.os_distro + ' ' + h.os_version) || 'OS ausstehend' }}
                        @if (h.reboot_required) {
                          · <strong style="color:var(--salmon-700);">Neustart nötig</strong>
                        }
                        · {{ h.container_count ?? h.containers_count ?? 0 }} Container
                      </span>
                    </div>
                    <span style="font-size:11px;font-weight:700;white-space:nowrap;">
                      {{ h.pending_apt_count ?? 0 }} APT-Pakete
                    </span>
                  </div>
                }
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>2. Dienste &amp; Anwendungen im Projekt</span>
                  <span>{{ proj.services.length }} Dienste</span>
                </div>
                @for (svc of proj.services; track svc.slug) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ svc.display_name }}</strong>
                      @if (svc.highest_cve_id) {
                        <span class="badge-eol" style="margin-left:6px;">{{ svc.highest_cve_id }}</span>
                      }
                      <span class="plan-item-sub" style="display:block;">
                        {{ svc.summary_line }}
                      </span>
                    </div>
                    <span style="white-space:nowrap;font-size:11px;">
                      {{ svc.current_version_summary || 'main' }} → <strong>{{ svc.target_version }}</strong>
                    </span>
                  </div>
                } @empty {
                  <div class="plan-item">
                    <span class="plan-item-sub">Reiner Infrastruktur-/System-Host ohne eigene App-Pipeline</span>
                  </div>
                }
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>3. Offene GitHub-PRs im Projekt</span>
                  <span style="color:var(--success);">{{ projectPrs(proj).length }} PRs</span>
                </div>
                @for (gt of projectPrs(proj).slice(0, 8); track gt.repo_full_name + gt.file_path + gt.pr_number) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ gt.repo_full_name }}</strong>
                      <span class="plan-item-sub" style="display:block;">
                        {{ gt.file_path }}
                        @if (gt.pr_number && gt.pr_url) {
                          ·
                          <a
                            [href]="gt.pr_url"
                            target="_blank"
                            rel="noopener"
                            style="color:var(--bluefly-600);text-decoration:none;font-weight:600;"
                          >
                            PR #{{ gt.pr_number }} ↗
                          </a>
                        }
                      </span>
                    </div>
                    <span style="color:var(--bluefly-500);font-weight:700;white-space:nowrap;">
                      Bereit zum Merge
                    </span>
                  </div>
                } @empty {
                  <div class="plan-item">
                    <span class="plan-item-sub">Keine offenen GitHub-PRs für dieses Projekt</span>
                  </div>
                }
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>4. Manuelles Projekt-Runbook</span>
                  <span>Kein Auto-Patching</span>
                </div>
                <pre
                  style="background:var(--neutral-900);color:#fff;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto;margin:0;line-height:1.45;"
                ><code>{{ buildProjectRunbook(proj) }}</code></pre>
              </div>

              @if (copiedFeedback()) {
                <div class="plan-block" style="border-color:var(--success);background:#f0fdf4;">
                  <span style="font-size:12px;font-weight:600;color:var(--success);">
                    ✓ Projekt-Runbook in die Zwischenablage kopiert
                  </span>
                </div>
              }

              <button
                type="button"
                id="execute-plan-btn"
                class="btn-primary"
                (click)="copyProjectRunbook(proj)"
              >
                Projekt-Runbook kopieren ({{ proj.hosts.length }} Hosts · {{ proj.services.length }} Dienste)
              </button>

              <p class="plan-check-note">
                Alle Wartungsbefehle für die Hosts und Dienste dieses Projekts werden in deine
                Zwischenablage kopiert, damit du sie selbst im eigenen Terminal ausführen kannst.
              </p>
            </div>
          </aside>
        }
      </div>
    </main>
  `,
})
export class ProjectsPage implements OnInit {
  private readonly api = inject(PatchbotApi);
  private readonly sanitizer = inject(DomSanitizer);

  readonly projects = signal<ProjectDto[]>([]);
  readonly selectedSlug = signal<string>('');
  readonly copiedFeedback = signal<boolean>(false);

  readonly actionRequiredProjects = computed(() =>
    this.projects().filter((p) => p.category === 'action_required'),
  );

  readonly readyProjects = computed(() =>
    this.projects().filter((p) => p.category !== 'action_required'),
  );

  readonly selectedProject = computed<ProjectDto | null>(() => {
    const list = this.projects();
    if (list.length === 0) {
      return null;
    }
    const slug = this.selectedSlug();
    return list.find((p) => p.slug === slug) ?? list[0];
  });

  constructor() {
    effect(() => {
      const tick = this.api.refreshTick();
      if (tick > 0) {
        this.loadProjects();
      }
    });
  }

  ngOnInit(): void {
    this.loadProjects();
  }

  loadProjects(): void {
    this.api.listProjects().subscribe((items) => {
      this.projects.set(items);
      if (items.length > 0 && !this.selectedSlug()) {
        const wuerth = items.find((p) => p.slug === 'hetzner-wuerth');
        this.selectedSlug.set((wuerth ?? items[0]).slug);
      }
    });
  }

  selectProject(proj: ProjectDto): void {
    this.selectedSlug.set(proj.slug);
    this.copiedFeedback.set(false);
  }

  renderLogo(key: string, name: string): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(getLogoSvg(key, name));
  }

  projectPrs(proj: ProjectDto): GitTargetDto[] {
    const all: GitTargetDto[] = [];
    for (const svc of proj.services) {
      for (const gt of svc.git_targets ?? []) {
        all.push(gt);
      }
    }
    return all;
  }

  buildProjectRunbook(proj: ProjectDto): string {
    const lines: string[] = [];
    lines.push(`# === Projekt: ${proj.display_name} (${proj.slug}) ===`);
    for (const h of proj.hosts) {
      lines.push(`# Host: ${h.hostname} (${h.distro || h.os_distro + ' ' + h.os_version})`);
      if ((h.pending_apt_count ?? 0) > 0) {
        lines.push(
          `ssh root@${h.hostname} "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y"`,
        );
      }
      for (const c of h.containers ?? []) {
        if (c.working_dir && c.working_dir.startsWith('/opt/')) {
          lines.push(
            `ssh root@${h.hostname} "cd ${c.working_dir} && git status --porcelain && git pull --ff-only && docker compose pull && docker compose up -d"`,
          );
          break;
        }
      }
    }
    return lines.join('\n');
  }

  copyProjectRunbook(proj: ProjectDto): void {
    const text = this.buildProjectRunbook(proj);
    if (text && typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).then(
        () => this.copiedFeedback.set(true),
        () => {},
      );
    } else {
      this.copiedFeedback.set(true);
    }
  }
}
