import { NgTemplateOutlet } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { AmpelBanner } from '../components/ampel-banner';
import { FindingDetail } from '../components/finding-detail';
import { DashboardDto, FindingDto, PatchbotApi } from '../core/patchbot-api';

type Mode = 'security' | 'maintenance' | 'filtered';
type Grouping = 'effort' | 'project';
type BucketKey = 'simple' | 'complex' | 'waiting_live';

const BUCKETS: { key: BucketKey; label: string; hint: string }[] = [
  { key: 'simple', label: '1. Einfache Fixes', hint: 'Frist 2 Werktage' },
  { key: 'complex', label: '2. Komplexe Eingriffe', hint: 'Frist 5 Werktage' },
  { key: 'waiting_live', label: '3. Gemergt – wartet auf Live-Gang', hint: 'Frist 1 Werktag' },
];

const DATE_FMT = new Intl.DateTimeFormat('de-DE', {
  day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Berlin',
});

@Component({
  selector: 'app-triage-dashboard',
  standalone: true,
  imports: [AmpelBanner, FindingDetail, NgTemplateOutlet],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1 class="page-title">Triage-Dashboard</h1>
          <p class="page-sub">Sicherheitslücken mit Handlungsbedarf, Zuständigkeit und Live-Verifikation.</p>
        </div>
      </div>

      @if (data(); as d) {
        <app-ampel-banner [ampel]="d.ampel" />

        <div class="toolbar">
          <div class="segmented" aria-label="Ansicht">
            <button type="button" data-mode="security" [class.active]="mode() === 'security'" (click)="mode.set('security')">
              Sicherheits-Triage
            </button>
            <button type="button" data-mode="maintenance" [class.active]="mode() === 'maintenance'" (click)="mode.set('maintenance')">
              Wartungs-Updates (ohne CVE) · {{ d.maintenance.length }}
            </button>
            <button type="button" data-mode="filtered" [class.active]="mode() === 'filtered'" (click)="mode.set('filtered')">
              Automatisch gefiltert · {{ d.filtered.length }}
            </button>
          </div>
          @if (mode() === 'security') {
            <div class="segmented" aria-label="Gruppierung">
              <button type="button" data-group="effort" [class.active]="grouping() === 'effort'" (click)="grouping.set('effort')">
                Nach Aufwand
              </button>
              <button type="button" data-group="project" [class.active]="grouping() === 'project'" (click)="grouping.set('project')">
                Nach Projekt
              </button>
            </div>
            <label class="toggle">
              <input id="only-mine" type="checkbox" [checked]="onlyMine()" (change)="onlyMine.set(!onlyMine())" />
              Nur meine Aufgaben
            </label>
          }
        </div>

        <div class="workspace">
          <section>
            @switch (mode()) {
              @case ('security') {
                @if (grouping() === 'effort') {
                  @for (bucket of buckets; track bucket.key) {
                    <div class="group-section" [attr.data-bucket]="bucket.key">
                      <div class="group-head">
                        <span class="group-name">{{ bucket.label }}</span>
                        <span class="group-count">{{ mine(d.buckets[bucket.key]).length }} · {{ bucket.hint }}</span>
                      </div>
                      <ul class="service-list">
                        @for (f of mine(d.buckets[bucket.key]); track f.id) {
                          <ng-container *ngTemplateOutlet="row; context: { $implicit: f }" />
                        } @empty {
                          <li class="empty-state">Nichts zu tun.</li>
                        }
                      </ul>
                    </div>
                  }
                } @else {
                  @for (group of projectGroups(); track group.name) {
                    <div class="group-section">
                      <div class="group-head">
                        <span class="group-name">{{ group.name }}</span>
                        <span class="group-count">{{ group.findings.length }}</span>
                      </div>
                      <ul class="service-list">
                        @for (f of group.findings; track f.id) {
                          <ng-container *ngTemplateOutlet="row; context: { $implicit: f }" />
                        }
                      </ul>
                    </div>
                  } @empty {
                    <p class="empty-state">Keine offenen Sicherheits-Aufgaben.</p>
                  }
                }
              }
              @case ('maintenance') {
                <div class="group-section">
                  <div class="group-head">
                    <span class="group-name">Wartungs-Updates ohne bekannte CVE</span>
                    <span class="group-count">keine Fristen, keine DMs</span>
                  </div>
                  <ul class="service-list">
                    @for (u of d.maintenance; track u.id) {
                      <li class="maintenance-row">
                        <div class="finding-main">
                          <div class="finding-title">{{ u.package_name }} {{ u.current_version || '?' }} → {{ u.target_version }}</div>
                          <div class="finding-sub">{{ u.project.name }} · {{ u.repository }} · CI: {{ u.ci_status || '–' }}</div>
                          @if (u.summary_de) {
                            <div class="finding-sub">{{ u.summary_de }}</div>
                          }
                        </div>
                        <span class="type-badge" [attr.data-type]="u.update_type">{{ u.update_type }}</span>
                        <a class="pr-badge" [href]="u.pr_url" target="_blank" rel="noopener">PR #{{ u.pr_number }}</a>
                        <button type="button" class="btn-link" (click)="requestAnalysis(u.id)">Analyse anfordern</button>
                      </li>
                    } @empty {
                      <li class="empty-state">Keine offenen Wartungs-Updates.</li>
                    }
                  </ul>
                  @if (notice()) {
                    <p class="plan-check-note">{{ notice() }}</p>
                  }
                </div>
              }
              @case ('filtered') {
                <div class="group-section">
                  <div class="group-head">
                    <span class="group-name">Automatisch gefiltert (Policy-Gate)</span>
                    <span class="group-count">{{ d.filtered.length }}</span>
                  </div>
                  <ul class="service-list">
                    @for (f of d.filtered; track f.id) {
                      <ng-container *ngTemplateOutlet="row; context: { $implicit: f }" />
                    } @empty {
                      <li class="empty-state">Keine automatisch gefilterten Findings.</li>
                    }
                  </ul>
                </div>
              }
            }
          </section>

          <aside class="detail-col">
            @if (selectedId(); as id) {
              <app-finding-detail [findingId]="id" (changed)="reload()" />
            } @else {
              <div class="plan-card">
                <div class="plan-panel">
                  <p class="plan-meta">Wähle links ein Finding, um Analyse, Frist, PR und Live-Verifikation zu sehen.</p>
                </div>
              </div>
            }
          </aside>
        </div>
      } @else {
        <p class="page-sub">Lade Dashboard…</p>
      }

      <ng-template #row let-f>
        <li class="finding-row" [class.selected]="selectedId() === f.id" [class.overdue]="f.overdue" (click)="selectedId.set(f.id)">
          <span class="sev-badge" [attr.data-sev]="f.highest_severity">{{ f.highest_severity }}</span>
          <div class="finding-main">
            <div class="finding-title">
              {{ f.title }}
              @if (f.kev_listed) {
                <span class="kev-badge" title="Aktiv ausgenutzt (CISA KEV)">KEV</span>
              }
            </div>
            <div class="finding-sub">{{ f.project.name }} · {{ f.vulnerability_ids.join(', ') }}</div>
          </div>
          <div class="finding-assignee">{{ f.assignee?.name ?? 'Nicht zugewiesen' }}</div>
          <div class="finding-deadline" [class.crit]="f.overdue">{{ deadlineText(f) }}</div>
          @if (f.pr) {
            <span class="pr-badge">PR #{{ f.pr.number }}{{ f.pr.draft ? ' · Draft' : '' }}</span>
          }
        </li>
      </ng-template>
    </main>
  `,
})
export class TriageDashboard implements OnInit {
  private readonly api = inject(PatchbotApi);
  readonly buckets = BUCKETS;
  readonly data = signal<DashboardDto | null>(null);
  readonly mode = signal<Mode>('security');
  readonly grouping = signal<Grouping>('effort');
  readonly onlyMine = signal(false);
  readonly selectedId = signal<number | null>(null);
  readonly notice = signal('');

  readonly projectGroups = computed(() => {
    const d = this.data();
    if (!d) return [];
    const all = this.mine([...d.buckets.simple, ...d.buckets.complex, ...d.buckets.waiting_live]);
    const groups = new Map<string, FindingDto[]>();
    for (const f of all) groups.set(f.project.name, [...(groups.get(f.project.name) ?? []), f]);
    return [...groups.entries()]
      .sort(([a], [b]) => a.localeCompare(b, 'de'))
      .map(([name, findings]) => ({ name, findings }));
  });

  ngOnInit(): void {
    this.reload();
  }

  reload(): void {
    this.api.getDashboard().subscribe((d) => this.data.set(d));
  }

  mine(list: FindingDto[]): FindingDto[] {
    const meId = this.data()?.me_id;
    return this.onlyMine() ? list.filter((f) => f.assignee?.id === meId) : list;
  }

  deadlineText(f: FindingDto): string {
    if (!f.deadline_at) return '';
    return f.overdue ? 'überfällig' : `Frist ${DATE_FMT.format(new Date(f.deadline_at))}`;
  }

  requestAnalysis(id: number): void {
    this.api.requestMaintenanceAnalysis(id).subscribe({
      next: () => this.notice.set('Analyse angefordert – das Ergebnis erscheint als Kommentar im PR.'),
      error: () => this.notice.set('Analyse konnte nicht angefordert werden.'),
    });
  }
}
