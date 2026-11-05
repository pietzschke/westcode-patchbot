import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { AuthService } from '../core/auth';
import { AssetDto, PatchbotApi, TriageProjectsDto } from '../core/patchbot-api';

const DEPLOYMENT_MODES = [
  { value: 'UNKNOWN', label: 'Unbekannt' },
  { value: 'CONTAINER', label: 'Container-Image' },
  { value: 'HOST_CHECKOUT', label: 'Git-Checkout auf Host' },
  { value: 'NONE', label: 'Wird nicht deployt' },
];

@Component({
  selector: 'app-projects-page',
  standalone: true,
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1 class="page-title">Projekte &amp; Zuordnung</h1>
          <p class="page-sub">Aktive Notion-Projekte mit ihren Repositories, Hosts und Containern.</p>
        </div>
        @if (auth.isAdmin()) {
          <button type="button" id="notion-sync-btn" class="btn-secondary btn-standard" style="width:auto;" (click)="syncNotion()">
            Notion jetzt synchronisieren
          </button>
        }
      </div>
      @if (notice()) {
        <p class="plan-check-note">{{ notice() }}</p>
      }

      @if (data(); as d) {
        <section class="group-section">
          <div class="group-head">
            <span class="group-name">Unzugeordnete Assets</span>
            <span class="group-count">{{ inbox().length }}</span>
          </div>
          <ul class="service-list">
            @for (asset of inbox(); track asset.type + asset.id) {
              <li class="inbox-row">
                <div class="finding-main">
                  <div class="finding-title">{{ asset.name }}</div>
                  <div class="finding-sub">
                    {{ typeLabel(asset.type) }}
                    @if (asset.suggested_project) {
                      · Vorschlag: {{ asset.suggested_project.name }}
                    }
                  </div>
                </div>
                @if (auth.isAdmin()) {
                  @if (asset.suggested_project) {
                    <button type="button" class="btn-link confirm-btn" (click)="confirm(asset)">Vorschlag übernehmen</button>
                  }
                  <select class="assign-select" (change)="assignTarget.set(key(asset), $any($event.target).value)">
                    <option value="">Projekt wählen…</option>
                    @for (p of d.projects; track p.slug) {
                      <option [value]="p.slug">{{ p.name }}</option>
                    }
                  </select>
                  <button type="button" class="btn-link assign-btn" (click)="assign(asset)">Zuordnen</button>
                }
              </li>
            } @empty {
              <li class="empty-state">Alle Assets sind einem Projekt zugeordnet.</li>
            }
          </ul>
        </section>

        @for (p of d.projects; track p.slug) {
          <section class="group-section project-card" [attr.data-project]="p.slug">
            <div class="group-head">
              <span class="group-name">
                {{ p.name }}
                @if (p.is_internal) {
                  <span class="type-badge">intern</span>
                }
                @if (p.notion_missing) {
                  <span class="sev-badge notion-missing" data-sev="HIGH">Nicht mehr in Notion</span>
                }
              </span>
              <span class="group-count">
                {{ p.notion_status || '–' }} · Owner: {{ p.owner?.name ?? 'keiner' }} · {{ p.open_findings }} offen
                @if (auth.isAdmin()) {
                  <label class="toggle monitoring-toggle">
                    <input type="checkbox" [checked]="p.is_monitored" (click)="toggleMonitoring(p.slug, !p.is_monitored)" />
                    überwacht
                  </label>
                } @else if (!p.is_monitored) {
                  · nicht überwacht
                }
              </span>
            </div>
            <ul class="service-list">
              @for (r of p.repositories; track r.id) {
                <li class="asset-row">
                  <span class="finding-title">{{ r.name }}</span>
                  @if (auth.isAdmin()) {
                    <select class="deployment-select" (change)="setDeployment(r, $any($event.target).value)">
                      @for (m of deploymentModes; track m.value) {
                        <option [value]="m.value" [selected]="m.value === r.deployment_mode">{{ m.label }}</option>
                      }
                    </select>
                  } @else {
                    <span class="finding-sub">{{ deploymentLabel(r.deployment_mode) }}</span>
                  }
                </li>
              }
              @for (h of p.hosts; track h.id) {
                <li class="asset-row"><span>{{ h.name }}</span><span class="finding-sub">Host</span></li>
              }
              @if (p.repositories.length === 0 && p.hosts.length === 0) {
                <li class="empty-state">Noch keine Assets zugeordnet.</li>
              }
            </ul>
          </section>
        }
      } @else {
        <p class="page-sub">Lade Projekte…</p>
      }
    </main>
  `,
})
export class ProjectsPage implements OnInit {
  private readonly api = inject(PatchbotApi);
  readonly auth = inject(AuthService);
  readonly deploymentModes = DEPLOYMENT_MODES;
  readonly data = signal<TriageProjectsDto | null>(null);
  readonly notice = signal('');
  readonly assignTarget = new Map<string, string>();

  readonly inbox = computed<AssetDto[]>(() => {
    const u = this.data()?.unassigned_assets;
    return u ? [...u.repositories, ...u.hosts, ...u.containers] : [];
  });

  ngOnInit(): void {
    this.reload();
  }

  reload(): void {
    this.api.listTriageProjects().subscribe((d) => this.data.set(d));
  }

  key(asset: AssetDto): string {
    return `${asset.type}:${asset.id}`;
  }

  typeLabel(type: string): string {
    return type === 'repository' ? 'Repository' : type === 'host' ? 'Host' : 'Container';
  }

  deploymentLabel(mode?: string): string {
    return DEPLOYMENT_MODES.find((m) => m.value === mode)?.label ?? 'Unbekannt';
  }

  confirm(asset: AssetDto): void {
    this.api.confirmSuggestion(asset.type, asset.id).subscribe({
      next: () => this.reload(),
      error: () => this.notice.set('Vorschlag konnte nicht übernommen werden.'),
    });
  }

  assign(asset: AssetDto): void {
    const slug = this.assignTarget.get(this.key(asset));
    if (!slug) {
      this.notice.set('Bitte zuerst ein Projekt wählen.');
      return;
    }
    this.api.assignAsset(asset.type, asset.id, slug).subscribe({
      next: () => this.reload(),
      error: () => this.notice.set('Zuordnung fehlgeschlagen.'),
    });
  }

  toggleMonitoring(slug: string, monitored: boolean): void {
    this.api.setMonitoring(slug, monitored).subscribe({
      next: () => this.reload(),
      error: () => this.notice.set('Überwachung konnte nicht geändert werden.'),
    });
  }

  setDeployment(repo: AssetDto, mode: string): void {
    this.api.setDeploymentMode(repo.id, mode).subscribe({
      next: () => this.notice.set(`Deployment-Art von ${repo.name} gespeichert.`),
      error: () => this.notice.set('Deployment-Art konnte nicht gespeichert werden.'),
    });
  }

  syncNotion(): void {
    this.api.syncNotion().subscribe({
      next: () => this.notice.set('Notion-Sync gestartet.'),
      error: () => this.notice.set('Notion-Sync läuft bereits oder ist fehlgeschlagen.'),
    });
  }
}
