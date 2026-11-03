import { Component, OnInit, computed, effect, inject, signal } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { getLogoSvg } from '../core/logos';
import { PatchbotApi, RolloutPlanDto } from '../core/patchbot-api';

@Component({
  selector: 'app-rollouts-page',
  standalone: true,
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1 class="page-title">Rollout-Historie</h1>
          <p class="page-sub">
            Alle erstellten und ausgeführten Rollout-Pläne inkl. Pre-Check-Ergebnis, GitHub-PR-Merge
            und seriellem Canary-Status pro Host.
          </p>
        </div>
      </div>

      @if (plans().length === 0) {
        <div
          style="background:#fff;border:1px solid var(--neutral-200);border-radius:8px;padding:32px;text-align:center;color:var(--neutral-600);"
        >
          Noch keine Rollout-Pläne vorhanden. Wähle unter <strong>Nach Dienst</strong> einen Dienst
          aus und klicke auf <strong>Plan ausführen</strong> oder <strong>Nur Git-PRs öffnen</strong>.
        </div>
      } @else {
        <div class="workspace">
          <div>
            <section class="group-section" aria-label="Rollout-Pläne">
              <div class="group-head">
                <span>Letzte Rollout-Pläne</span>
                <span class="group-count">{{ plans().length }} Pläne</span>
              </div>
              <ul class="service-list">
                @for (plan of plans(); track plan.id) {
                  <li
                    class="service-row"
                    [class.selected]="selectedPlan()?.id === plan.id"
                    (click)="selectedPlanId.set(plan.id)"
                  >
                    <div
                      class="svc-logo"
                      [innerHTML]="
                        renderLogo(
                          plan.service_logo_key || plan.service_slug,
                          plan.service_display_name || plan.service_slug
                        )
                      "
                    ></div>
                    <div class="svc-main">
                      <div class="svc-title">
                        {{ plan.service_display_name || plan.service_slug }}
                      </div>
                      <div class="svc-sub">
                        @if (plan.block_reason) {
                          <span class="crit-text">{{ plan.block_reason }}</span>
                        } @else {
                          Plan {{ plan.id.slice(0, 8) }} · {{ formatTime(plan.created_at) }}
                        }
                      </div>
                    </div>
                    <div class="svc-version">
                      <span
                        class="status-pill"
                        [class.crit]="plan.status === 'BLOCKED' || plan.status === 'ROLLED_BACK'"
                        [class.ok]="plan.status === 'SUCCEEDED' || plan.status === 'READY'"
                      >
                        {{ plan.status }}
                      </span>
                    </div>
                    <div class="svc-scope">
                      <span>{{ plan.steps.length }} Schritte</span>
                    </div>
                    <div class="svc-chevron">›</div>
                  </li>
                }
              </ul>
            </section>
          </div>

          @if (selectedPlan(); as plan) {
            <aside
              class="plan-stripe-wrap plan-card"
              [class.crit]="plan.status === 'BLOCKED' || plan.status === 'ROLLED_BACK'"
            >
              <div class="plan-panel">
                <div class="plan-header">
                  <div
                    class="svc-logo"
                    style="background:#fff;"
                    [innerHTML]="
                      renderLogo(
                        plan.service_logo_key || plan.service_slug,
                        plan.service_display_name || plan.service_slug
                      )
                    "
                  ></div>
                  <div class="plan-header-text">
                    <span
                      class="plan-kicker"
                      [class.crit]="plan.status === 'BLOCKED' || plan.status === 'ROLLED_BACK'"
                    >
                      Rollout-Plan · {{ plan.status }}
                    </span>
                    <div class="plan-title">
                      {{ plan.service_display_name || plan.service_slug }}
                    </div>
                    <div class="plan-meta">
                      Plan-ID {{ plan.id.slice(0, 8) }} · {{ formatTime(plan.created_at) }}
                    </div>
                  </div>
                </div>

                @if (plan.block_reason) {
                  <div class="plan-block">
                    <div class="plan-block-title">
                      <span>Pre-Check / Blockierung</span>
                      <span style="color:var(--salmon-700);">Blockiert</span>
                    </div>
                    <div class="plan-item">
                      <span style="color:var(--salmon-700);">{{ plan.block_reason }}</span>
                    </div>
                  </div>
                }

                <div class="plan-block">
                  <div class="plan-block-title">
                    <span>Ausführungsschritte (Seriell)</span>
                    <span>{{ plan.steps.length }} Schritte</span>
                  </div>
                  @for (step of plan.steps; track step.id) {
                    <div class="plan-item">
                      <div>
                        <span class="host">#{{ step.order }}</span>
                        @if (step.step_type === 'github_merge') {
                          <span>
                            GitHub PR
                            @if (step.pr_url) {
                              <a
                                [href]="step.pr_url"
                                target="_blank"
                                rel="noopener"
                                style="color:var(--bluefly-600);text-decoration:none;font-weight:600;"
                              >
                                #{{ step.pr_number }} ↗
                              </a>
                            } @else {
                              #{{ step.pr_number }}
                            }
                            ({{ step.repo_full_name }})
                          </span>
                        } @else {
                          <span>
                            {{ step.hostname }} ·
                            <span class="path">{{ step.working_dir || step.step_type }}</span>
                          </span>
                        }
                      </div>
                      <span class="git-ok">
                        <span
                          class="dot"
                          [class.ok]="step.status === 'SUCCEEDED'"
                          [class.crit]="step.status === 'ROLLED_BACK' || step.status === 'ABORTED'"
                          [class.hint]="step.status === 'PENDING' || step.status === 'DISPATCHED'"
                        ></span>
                        {{ step.status }}
                      </span>
                    </div>
                  }
                </div>
              </div>
            </aside>
          }
        </div>
      }
    </main>
  `,
})
export class RolloutsPage implements OnInit {
  private readonly api = inject(PatchbotApi);
  private readonly sanitizer = inject(DomSanitizer);

  readonly plans = signal<RolloutPlanDto[]>([]);
  readonly selectedPlanId = signal<string>('');

  readonly selectedPlan = computed<RolloutPlanDto | null>(() => {
    const list = this.plans();
    if (list.length === 0) {
      return null;
    }
    const id = this.selectedPlanId();
    return list.find((p) => p.id === id) ?? list[0];
  });

  constructor() {
    effect(() => {
      this.api.refreshTick();
      this.loadPlans();
    });
  }

  ngOnInit(): void {
    this.loadPlans();
  }

  loadPlans(): void {
    this.api.listPlans().subscribe((items) => {
      this.plans.set(items);
      if (items.length > 0 && !this.selectedPlanId()) {
        this.selectedPlanId.set(items[0].id);
      }
    });
  }

  renderLogo(key: string, name: string): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(getLogoSvg(key, name));
  }

  formatTime(iso: string): string {
    if (!iso) {
      return '';
    }
    try {
      return new Date(iso).toLocaleString('de-DE', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return iso;
    }
  }
}
