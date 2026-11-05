import { Component, OnInit, computed, effect, inject, signal } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { getLogoSvg } from '../core/logos';
import { PatchbotApi, ServiceGroupDto } from '../core/patchbot-api';

@Component({
  selector: 'app-services-page',
  standalone: true,
  template: `
    <main class="page">
      <div class="page-head" style="display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;">
        <div>
          <h1 class="page-title">Nach Dienst</h1>
          <p class="page-sub">
            Nur behebbare Sicherheitslücken und ausstehende Rollouts auf laufenden Systemen.
            Klicke auf einen Dienst für das manuelle Runbook.
          </p>
        </div>
        <div
          role="tablist"
          aria-label="Gruppierung"
          style="display:inline-flex;background:var(--neutral-100);padding:3px;border-radius:8px;border:1px solid var(--neutral-200);gap:2px;"
        >
          <span
            role="tab"
            [attr.aria-selected]="groupBy() === 'urgency'"
            style="cursor:pointer;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;"
            [style.background]="groupBy() === 'urgency' ? '#fff' : 'transparent'"
            [style.color]="groupBy() === 'urgency' ? 'var(--neutral-900)' : 'var(--neutral-600)'"
            (click)="groupBy.set('urgency')"
          >
            Nach Dringlichkeit
          </span>
          <span
            role="tab"
            [attr.aria-selected]="groupBy() === 'project'"
            style="cursor:pointer;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;"
            [style.background]="groupBy() === 'project' ? '#fff' : 'transparent'"
            [style.color]="groupBy() === 'project' ? 'var(--neutral-900)' : 'var(--neutral-600)'"
            (click)="groupBy.set('project')"
          >
            Nach Projekt gruppiert
          </span>
        </div>
      </div>

      <div class="workspace">
        <div>
          @if (groupBy() === 'urgency') {
            <section class="group-section" aria-label="Jetzt handeln">
              <div class="group-head">
                <span>Jetzt handeln · Sicherheits-Updates mit verfügbarem Fix</span>
                <span class="group-count">{{ actionRequiredServices().length }} Dienste</span>
              </div>
              <ul class="service-list">
                @for (svc of actionRequiredServices(); track svc.slug) {
                  <li
                    class="service-row"
                    [class.selected]="selectedService()?.slug === svc.slug"
                    [id]="'row-' + svc.slug"
                    (click)="selectService(svc)"
                  >
                    <div
                      class="svc-logo"
                      [attr.title]="svc.display_name"
                      [innerHTML]="renderLogo(svc.logo_key, svc.display_name)"
                    ></div>
                    <div class="svc-main">
                      <div class="svc-title">
                        {{ svc.display_name }}
                        @if (svc.projects && svc.projects.length > 0 && svc.slug !== 'ubuntu-apt' && svc.slug !== 'ubuntu-eol') {
                          <span style="font-size:11px;font-weight:500;color:var(--neutral-500);margin-left:6px;">
                            · {{ svc.projects[0].display_name }}
                          </span>
                        }
                      </div>
                      <div class="svc-sub">
                        @if (svc.highest_cve_id) {
                          <span class="crit-text">{{ svc.highest_cve_id }}</span> ·
                        }
                        {{ svc.summary_line }}
                      </div>
                    </div>
                    <div class="svc-version">
                      @if (svc.current_version_summary && svc.target_version) {
                        <span class="old">{{ svc.current_version_summary }}</span> →
                        <span class="new">{{ svc.target_version }}</span>
                      } @else {
                        <span class="new">{{ svc.target_version || svc.current_version_summary }}</span>
                      }
                    </div>
                    <div class="svc-scope">
                      <span class="dot crit"></span>
                      <span>{{ svc.git_targets.length }} Git · {{ svc.host_targets.length }} Hosts</span>
                    </div>
                    <div class="svc-chevron">›</div>
                  </li>
                }
              </ul>
            </section>

            <section class="group-section" aria-label="Bereit zum Ausrollen">
              <div class="group-head">
                <span>Bereit zum Ausrollen · Neue Versionen &amp; Host-Updates</span>
                <span class="group-count">{{ readyServices().length }} Dienste</span>
              </div>
              <ul class="service-list">
                @for (svc of readyServices(); track svc.slug) {
                  <li
                    class="service-row"
                    [class.selected]="selectedService()?.slug === svc.slug"
                    [id]="'row-' + svc.slug"
                    (click)="selectService(svc)"
                  >
                    <div
                      class="svc-logo"
                      [attr.title]="svc.display_name"
                      [innerHTML]="renderLogo(svc.logo_key, svc.display_name)"
                    ></div>
                    <div class="svc-main">
                      <div class="svc-title">{{ svc.display_name }}</div>
                      <div class="svc-sub">{{ svc.summary_line }}</div>
                    </div>
                    <div class="svc-version">
                      @if (svc.current_version_summary && svc.target_version) {
                        <span class="old">{{ svc.current_version_summary }}</span> →
                        <span class="new">{{ svc.target_version }}</span>
                      } @else {
                        <span class="new">{{ svc.target_version || svc.current_version_summary }}</span>
                      }
                    </div>
                    <div class="svc-scope">
                      <span class="dot hint"></span>
                      <span>{{ svc.git_targets.length }} Git · {{ svc.host_targets.length }} Hosts</span>
                    </div>
                    <div class="svc-chevron">›</div>
                  </li>
                }
              </ul>
            </section>
          } @else {
            @for (group of servicesByProject(); track group.projectSlug) {
              <section class="group-section" [attr.aria-label]="group.projectName">
                <div class="group-head">
                  <span>{{ group.projectName }} · <span style="font-weight:400;text-transform:none;">{{ group.hostsSummary }}</span></span>
                  <span class="group-count">{{ group.services.length }} {{ group.services.length === 1 ? 'Dienst' : 'Dienste' }}</span>
                </div>
                <ul class="service-list">
                  @for (svc of group.services; track svc.slug) {
                    <li
                      class="service-row"
                      [class.selected]="selectedService()?.slug === svc.slug"
                      [id]="'row-' + group.projectSlug + '-' + svc.slug"
                      (click)="selectService(svc)"
                    >
                      <div
                        class="svc-logo"
                        [attr.title]="svc.display_name"
                        [innerHTML]="renderLogo(svc.logo_key, svc.display_name)"
                      ></div>
                      <div class="svc-main">
                        <div class="svc-title">{{ svc.display_name }}</div>
                        <div class="svc-sub">
                          @if (svc.highest_cve_id) {
                            <span class="crit-text">{{ svc.highest_cve_id }}</span> ·
                          }
                          {{ svc.summary_line }}
                        </div>
                      </div>
                      <div class="svc-version">
                        @if (svc.current_version_summary && svc.target_version) {
                          <span class="old">{{ svc.current_version_summary }}</span> →
                          <span class="new">{{ svc.target_version }}</span>
                        } @else {
                          <span class="new">{{ svc.target_version || svc.current_version_summary }}</span>
                        }
                      </div>
                      <div class="svc-scope">
                        <span class="dot" [class.crit]="svc.category === 'action_required'" [class.hint]="svc.category !== 'action_required'"></span>
                        <span>{{ svc.git_targets.length }} Git · {{ svc.host_targets.length }} Hosts</span>
                      </div>
                      <div class="svc-chevron">›</div>
                    </li>
                  }
                </ul>
              </section>
            }
          }
        </div>

        @if (selectedService(); as selected) {
          <aside
            class="plan-stripe-wrap plan-card"
            [class.crit]="selected.category === 'action_required'"
            id="plan-wrap"
          >
            <div class="plan-panel" id="plan-content">
              <div class="plan-header">
                <div
                  class="svc-logo"
                  style="background:#fff;"
                  [innerHTML]="renderLogo(selected.logo_key, selected.display_name)"
                ></div>
                <div>
                  <h2 class="plan-title" id="p-title">{{ selected.display_name }}</h2>
                  <div class="plan-meta" id="p-meta">
                    Update {{ selected.current_version_summary }} → {{ selected.target_version }}
                    @if (selected.highest_cve_id) {
                      · <strong style="color:var(--salmon-700);">{{ selected.highest_cve_id }}</strong>
                    }
                  </div>
                </div>
              </div>

              @if (selected.vulnerabilities && selected.vulnerabilities.length > 0) {
                <div class="plan-block" id="p-vuln-block">
                  <div class="plan-block-title">
                    <span>Gefundene Sicherheitslücken (Trivy)</span>
                    <span style="color:var(--salmon-700);">
                      {{ selected.vulnerabilities.length }} mit Fix
                    </span>
                  </div>
                  @for (vuln of selected.vulnerabilities.slice(0, 6); track vuln.vulnerability_id + vuln.package_name) {
                    <div class="plan-item" style="align-items:flex-start;">
                      <div style="max-width:72%;">
                        <strong style="color:var(--salmon-700);">{{ vuln.vulnerability_id }}</strong>
                        <span class="plan-item-sub" style="display:block;">
                          {{ vuln.package_name }} · {{ vuln.title }}
                        </span>
                      </div>
                      <span style="font-size:11px;font-weight:700;color:var(--neutral-700);white-space:nowrap;">
                        Fix: {{ vuln.fixed_version }}
                      </span>
                    </div>
                  }
                </div>
              }

              <div class="plan-block" id="p-git-block">
                <div class="plan-block-title">
                  <span>1. Git-Standorte / Renovate &amp; Dependabot PRs</span>
                  <span style="color:var(--success);">
                    {{ selected.git_targets.length }} PRs
                  </span>
                </div>
                @for (gt of selected.git_targets.slice(0, 8); track gt.repo_full_name + gt.file_path + gt.pr_number) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ gt.repo_full_name }}</strong>
                      <span class="plan-item-sub" style="display:block;">
                        {{ gt.file_path }}
                        @if (gt.pr_number) {
                          ·
                          @if (gt.pr_url) {
                            <a
                              [href]="gt.pr_url"
                              target="_blank"
                              rel="noopener"
                              style="color:var(--bluefly-600);text-decoration:none;font-weight:600;"
                            >
                              PR #{{ gt.pr_number }} ↗
                            </a>
                          } @else {
                            Renovate PR #{{ gt.pr_number }}
                          }
                        }
                      </span>
                    </div>
                    <span style="color:var(--bluefly-500);font-weight:700;white-space:nowrap;">
                      {{ gt.ci_status === 'success' ? 'Bereit zum Merge' : gt.ci_status }}
                    </span>
                  </div>
                } @empty {
                  <div class="plan-item">
                    <span class="plan-item-sub">Keine offenen Git-PRs erforderlich</span>
                  </div>
                }
              </div>

              <div class="plan-block" id="p-host-block">
                <div class="plan-block-title">
                  <span>2. Betroffene Hosts &amp; Manuelles Runbook ({{ selected.host_targets.length }} Hosts)</span>
                  <span>{{ allHostsClean(selected) ? 'Vorab-Check OK' : 'Git Dirty' }}</span>
                </div>
                @for (ht of selected.host_targets; track ht.hostname + ht.working_dir) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ ht.hostname }}</strong>
                      <span class="plan-item-sub" style="display:block;">
                        {{ ht.working_dir || ht.target_type }} ·
                        @if (ht.target_type === 'ecr_app') {
                          CircleCI Deploy nach Merge ·
                        }
                        {{ ht.git_clean !== false ? 'git clean' : 'git dirty' }}
                      </span>
                    </div>
                    <span style="white-space:nowrap;">
                      {{ ht.running_version }} → <strong>{{ ht.target_version }}</strong>
                    </span>
                  </div>
                } @empty {
                  <div class="plan-item">
                    <span class="plan-item-sub">Reines Repository-/Template-Update (kein direkter Host)</span>
                  </div>
                }
                @if (selected.host_targets.length > 0) {
                  <div style="margin-top:8px;">
                    <div style="font-size:11px;font-weight:700;color:var(--neutral-600);margin-bottom:4px;">
                      Manuelle Befehle (im eigenen Terminal ausführen):
                    </div>
                    <pre
                      style="background:var(--neutral-900);color:#fff;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto;margin:0;line-height:1.45;"
                    ><code>{{ buildManualRunbook(selected) }}</code></pre>
                  </div>
                }
              </div>

              @if (copiedFeedback()) {
                <div class="plan-block" style="border-color:var(--success);background:#f0fdf4;">
                  <span style="font-size:12px;font-weight:600;color:var(--success);">
                    ✓ Runbook-Befehle in die Zwischenablage kopiert
                  </span>
                </div>
              }

              <button
                type="button"
                id="copy-runbook-btn"
                class="btn-primary"
                (click)="copyRunbook(selected)"
              >
                Runbook kopieren ({{ selected.git_targets.length }} Git · {{ selected.host_targets.length }} Hosts)
              </button>

              @if (firstPrUrl(selected); as prUrl) {
                <button
                  type="button"
                  id="open-pr-btn"
                  class="btn-secondary btn-standard"
                  (click)="openPr(prUrl)"
                >
                  PR auf GitHub öffnen
                </button>
              }

              <p class="plan-check-note">
                Kein Live-Patching und kein SSH-Zugriff vom Patchbot aus: Das Runbook wird in deine
                Zwischenablage kopiert, damit du die Befehle selbst im eigenen Terminal ausführst.
              </p>
            </div>
          </aside>
        }
      </div>
    </main>
  `,
})
export class ServicesPage implements OnInit {
  private readonly api = inject(PatchbotApi);
  private readonly sanitizer = inject(DomSanitizer);

  readonly services = signal<ServiceGroupDto[]>([]);
  readonly selectedSlug = signal<string>('');
  readonly copiedFeedback = signal<boolean>(false);
  readonly groupBy = signal<'urgency' | 'project'>('urgency');

  readonly actionRequiredServices = computed(() =>
    this.services().filter((s) => s.category === 'action_required'),
  );

  readonly readyServices = computed(() =>
    this.services().filter((s) => s.category !== 'action_required'),
  );

  readonly servicesByProject = computed(() => {
    const groupsMap = new Map<
      string,
      { projectSlug: string; projectName: string; hosts: Set<string>; services: ServiceGroupDto[] }
    >();
    for (const svc of this.services()) {
      if (svc.slug === 'ubuntu-apt' || svc.slug === 'ubuntu-eol') {
        const key = 'system-fleet';
        if (!groupsMap.has(key)) {
          groupsMap.set(key, {
            projectSlug: key,
            projectName: 'Flottenweite Betriebssystem-Updates',
            hosts: new Set(),
            services: [],
          });
        }
        const entry = groupsMap.get(key)!;
        for (const ht of svc.host_targets) {
          entry.hosts.add(ht.hostname);
        }
        entry.services.push(svc);
        continue;
      }

      const projList =
        svc.projects && svc.projects.length > 0
          ? svc.projects
          : [{ slug: 'westcode-shared', display_name: 'Übergreifende Templates & Repos' }];

      for (const p of projList) {
        if (!groupsMap.has(p.slug)) {
          groupsMap.set(p.slug, {
            projectSlug: p.slug,
            projectName: p.display_name,
            hosts: new Set(),
            services: [],
          });
        }
        const entry = groupsMap.get(p.slug)!;
        for (const ht of svc.host_targets) {
          entry.hosts.add(ht.hostname);
        }
        entry.services.push(svc);
      }
    }

    return Array.from(groupsMap.values())
      .map((g) => ({
        projectSlug: g.projectSlug,
        projectName: g.projectName,
        hostsSummary: g.hosts.size > 0 ? Array.from(g.hosts).join(', ') : 'GitHub Repository',
        services: g.services,
      }))
      .sort((a, b) => b.services.length - a.services.length || a.projectName.localeCompare(b.projectName));
  });

  readonly selectedService = computed<ServiceGroupDto | null>(() => {
    const list = this.services();
    if (list.length === 0) {
      return null;
    }
    const slug = this.selectedSlug();
    return list.find((s) => s.slug === slug) ?? list[0];
  });

  constructor() {
    effect(() => {
      const tick = this.api.refreshTick();
      if (tick > 0) {
        this.loadServices();
      }
    });
  }

  ngOnInit(): void {
    this.loadServices();
  }

  loadServices(): void {
    this.api.listServices().subscribe((items) => {
      this.services.set(items);
      if (items.length > 0 && !this.selectedSlug()) {
        this.selectedSlug.set(items[0].slug);
      }
    });
  }

  selectService(service: ServiceGroupDto): void {
    this.selectedSlug.set(service.slug);
    this.copiedFeedback.set(false);
  }

  renderLogo(key: string, name: string): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(getLogoSvg(key, name));
  }

  allHostsClean(service: ServiceGroupDto): boolean {
    return service.host_targets.every((ht) => ht.git_clean !== false);
  }

  buildManualRunbook(service: ServiceGroupDto): string {
    return service.host_targets
      .map((ht) => {
        if (service.slug === 'ubuntu-apt' || ht.target_type === 'apt') {
          return `ssh root@${ht.hostname} "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y"`;
        }
        if (service.slug === 'ubuntu-eol' || ht.target_type === 'os_eol') {
          return `# ${ht.hostname}: Ubuntu 24.04 LTS Server-Image in westcode-infra aktualisieren & neu ausrollen`;
        }
        const dir = ht.working_dir || `/opt/${service.slug}`;
        return `ssh root@${ht.hostname} "cd ${dir} && git status --porcelain && git pull --ff-only && docker compose pull && docker compose up -d"`;
      })
      .join('\n');
  }

  firstPrUrl(service: ServiceGroupDto): string | null {
    return service.git_targets.find((gt) => !!gt.pr_url)?.pr_url ?? null;
  }

  openPr(url: string): void {
    if (typeof window !== 'undefined' && typeof window.open === 'function') {
      window.open(url, '_blank', 'noopener');
    }
  }

  copyRunbook(service: ServiceGroupDto): void {
    const runbook = this.buildManualRunbook(service);
    if (runbook && typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(runbook).then(
        () => this.copiedFeedback.set(true),
        () => {},
      );
    }
  }
}
