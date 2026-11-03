import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { switchMap } from 'rxjs';
import { getLogoSvg } from '../core/logos';
import { PatchbotApi, RolloutPlanDto, ServiceGroupDto } from '../core/patchbot-api';

@Component({
  selector: 'app-services-page',
  standalone: true,
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1 class="page-title">Nach Dienst</h1>
          <p class="page-sub">
            Nur behebbare Sicherheitslücken und ausstehende Rollouts auf laufenden Systemen.
            Klicke auf einen Dienst für den Rollout-Plan.
          </p>
        </div>
      </div>

      <div class="workspace">
        <div>
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
                      · {{ selected.highest_cve_id }}
                    }
                  </div>
                </div>
              </div>

              <div class="plan-block" id="p-git-block">
                <div class="plan-block-title">
                  <span>1. Git-Standorte / Renovate PR</span>
                  <span style="color:var(--success);">
                    {{ selected.git_targets.length }} Standorte
                  </span>
                </div>
                @for (gt of selected.git_targets; track gt.repo_full_name + gt.file_path) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ gt.repo_full_name }}</strong>
                      <span class="plan-item-sub">
                        {{ gt.file_path }}
                        @if (gt.pr_number) {
                          · Renovate PR #{{ gt.pr_number }}
                        }
                      </span>
                    </div>
                    <span style="color:var(--bluefly-500);font-weight:700;">
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
                  <span>2. Serieller Rollout &amp; Pre-Check ({{ selected.host_targets.length }} Hosts)</span>
                  <span>{{ allHostsClean(selected) ? 'Vorab-Check OK' : 'Git Dirty' }}</span>
                </div>
                @for (ht of selected.host_targets; track ht.hostname + ht.working_dir) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ ht.hostname }}</strong>
                      <span class="plan-item-sub">
                        {{ ht.working_dir }} · {{ ht.git_clean ? 'git clean' : 'git dirty' }}
                      </span>
                    </div>
                    <span>
                      {{ ht.running_version }} → <strong>{{ ht.target_version }}</strong>
                    </span>
                  </div>
                }
              </div>

              @if (activePlan(); as plan) {
                <div class="plan-block" id="p-status-block">
                  <div class="plan-block-title">
                    <span>Rollout-Status</span>
                    <strong>{{ plan.status }}</strong>
                  </div>
                  @if (plan.block_reason) {
                    <div class="plan-item">
                      <span style="color:var(--salmon-700);">{{ plan.block_reason }}</span>
                    </div>
                  }
                </div>
              }

              <button
                type="button"
                id="execute-plan-btn"
                class="btn-primary"
                (click)="executeSelectedPlan(selected)"
              >
                Plan ausführen ({{ selected.git_targets.length }} Git · {{ selected.host_targets.length }} Hosts)
              </button>

              <button
                type="button"
                class="btn-secondary btn-standard"
                (click)="preparePlanOnly(selected)"
              >
                Nur Git-PRs öffnen
              </button>

              <p class="plan-check-note">
                Rollt nacheinander aus: wartet je Host auf Healthcheck (60 s). Schlägt der erste Host
                fehl, wird er auf das vorige Image zurückgesetzt und die übrigen Hosts bleiben
                unberührt.
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
  readonly activePlan = signal<RolloutPlanDto | null>(null);

  readonly actionRequiredServices = computed(() =>
    this.services().filter((s) => s.category === 'action_required'),
  );

  readonly readyServices = computed(() =>
    this.services().filter((s) => s.category !== 'action_required'),
  );

  readonly selectedService = computed<ServiceGroupDto | null>(() => {
    const list = this.services();
    if (list.length === 0) {
      return null;
    }
    const slug = this.selectedSlug();
    return list.find((s) => s.slug === slug) ?? list[0];
  });

  ngOnInit(): void {
    this.api.listServices().subscribe((items) => {
      this.services.set(items);
      if (items.length > 0 && !this.selectedSlug()) {
        this.selectedSlug.set(items[0].slug);
      }
    });
  }

  selectService(service: ServiceGroupDto): void {
    this.selectedSlug.set(service.slug);
    this.activePlan.set(null);
  }

  renderLogo(key: string, name: string): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(getLogoSvg(key, name));
  }

  allHostsClean(service: ServiceGroupDto): boolean {
    return service.host_targets.every((ht) => ht.git_clean);
  }

  preparePlanOnly(service: ServiceGroupDto): void {
    this.api.createServicePlan(service.slug).subscribe((plan) => {
      this.activePlan.set(plan);
    });
  }

  executeSelectedPlan(service: ServiceGroupDto): void {
    this.api
      .createServicePlan(service.slug)
      .pipe(switchMap((plan) => this.api.executePlan(plan.id)))
      .subscribe((executedPlan) => {
        this.activePlan.set(executedPlan);
      });
  }
}
