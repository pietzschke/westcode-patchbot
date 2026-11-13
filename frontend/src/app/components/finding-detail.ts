import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { Observable, Subscription } from 'rxjs';
import { apiErrorText } from '../core/api-error';
import { findingSubline } from '../core/finding-text';
import { DismissPayload, FindingDetailDto, PatchbotApi, VerificationRowDto } from '../core/patchbot-api';

const STATE_LABELS: Record<string, string> = {
  NEW: 'Neu – wartet auf „Ich bin dran“',
  IN_PROGRESS: 'In Bearbeitung',
  PR_MERGED_WAITING_LIVE: 'Gemergt – wartet auf Live-Gang',
  VERIFIED_LIVE: 'Live verifiziert',
  RESOLVED_NO_DEPLOYMENT: 'Gemergt – kein Deployment',
  SNOOZED: 'Zurückgestellt',
  DISMISSED: 'Nicht betroffen',
  FILTERED_IRRELEVANT: 'Automatisch gefiltert',
  SUPPRESSED_UNMONITORED: 'Projekt nicht überwacht',
};
const SOURCE_LABELS: Record<string, string> = { SYSTEM: 'System', WEB: 'Web', SLACK: 'Slack', GITHUB: 'GitHub', NOTION: 'Notion' };
const PROOF_LABELS: Record<string, string> = { REVISION: 'Revision', CHECKOUT: 'Checkout', SCAN: 'Image-Scan' };
const OPEN_STATES = ['NEW', 'IN_PROGRESS', 'PR_MERGED_WAITING_LIVE'];
const REOPENABLE = ['DISMISSED', 'SNOOZED', 'FILTERED_IRRELEVANT'];
const MIN_REASON = 15;
const DATE_FMT = new Intl.DateTimeFormat('de-DE', {
  day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Berlin',
});

type DismissChoice = 'DISMISSED' | 'SNOOZED_14' | 'SNOOZED_30';

@Component({
  selector: 'app-finding-detail',
  standalone: true,
  template: `
    <div class="plan-card" [class.crit]="detail()?.highest_severity === 'CRITICAL'">
      <div class="plan-panel">
        @if (detail(); as f) {
          <div class="plan-header">
            <span class="sev-badge" [attr.data-sev]="f.highest_severity">{{ f.highest_severity }}</span>
            @if (f.kev_listed) {
              <span class="kev-badge" title="Aktiv ausgenutzt (CISA KEV)">KEV</span>
            }
          </div>
          <h2 class="plan-title" id="detail-title">{{ f.title }}</h2>
          <div class="plan-meta">{{ subline(f) }}</div>

          <div class="plan-block">
            <div class="plan-block-title"><span>Status</span></div>
            <div class="plan-item"><span class="state-label">{{ stateLabel(f.state) }}</span></div>
            <div class="plan-item">
              <span>Zuständig</span>
              <span>{{ f.assignee?.name ?? 'Nicht zugewiesen' }}</span>
            </div>
            @if (f.assigned_reason_de) {
              <div class="plan-item"><span class="plan-item-sub">{{ f.assigned_reason_de }}</span></div>
            }
            @if (f.deadline_at && isOpen()) {
              <div class="plan-item">
                <span>Frist</span>
                <span [class.crit]="f.overdue">{{ f.overdue ? 'überfällig seit ' : '' }}{{ fmt(f.deadline_at) }}</span>
              </div>
            }
            @if (f.dismissal) {
              <div class="plan-item">
                <span class="plan-item-sub">„{{ f.dismissal.reason }}“ – {{ f.dismissal.by?.name ?? 'System' }}</span>
              </div>
            }
          </div>

          @if (error()) {
            <p class="action-error" role="alert">{{ error() }}</p>
          }

          @if (f.state === 'NEW' || f.state === 'IN_PROGRESS') {
            <button type="button" id="ack-btn" class="btn-primary" [disabled]="busy()" (click)="acknowledge()">
              {{ f.state === 'NEW' ? 'Ich bin dran' : 'Aufgabe übernehmen' }}
            </button>
          }
          @if (isOpen()) {
            <div class="action-links">
              <button type="button" id="dismiss-open" class="btn-link" (click)="dismissOpen.set(!dismissOpen())">
                Snooze / Nicht betroffen
              </button>
              @if (f.extended_in_stage !== f.state) {
                <button type="button" id="extend-open" class="btn-link" (click)="extendOpen.set(!extendOpen())">
                  Frist einmalig verlängern
                </button>
              }
            </div>
          }
          @if (canReopen()) {
            <button type="button" id="reopen-btn" class="btn-secondary btn-standard" [disabled]="busy()" (click)="reopenFinding()">
              Wieder öffnen
            </button>
          }

          @if (dismissOpen() && isOpen()) {
            <div class="plan-block dialog-block">
              <label class="plan-block-title" for="dismiss-mode">Art</label>
              <select id="dismiss-mode" (change)="dismissChoice.set($any($event.target).value)">
                <option value="DISMISSED">Nicht betroffen</option>
                <option value="SNOOZED_14">Zurückstellen (14 Tage)</option>
                <option value="SNOOZED_30">Zurückstellen (30 Tage)</option>
              </select>
              <label class="plan-block-title" for="dismiss-reason">Begründung (Pflicht, mind. 15 Zeichen)</label>
              <textarea id="dismiss-reason" rows="3" (input)="dismissReason.set($any($event.target).value)"></textarea>
              @if (f.highest_severity === 'HIGH' || f.highest_severity === 'CRITICAL') {
                <p class="plan-check-note">Bei {{ f.highest_severity }} wird das Team im Slack-Channel informiert.</p>
              }
              <button type="button" id="dismiss-submit" class="btn-primary" [disabled]="!dismissValid() || busy()" (click)="dismiss()">
                Bestätigen
              </button>
            </div>
          }

          @if (extendOpen() && isOpen()) {
            <div class="plan-block dialog-block">
              <label class="plan-block-title" for="extend-reason">Grund der Verlängerung (mind. 15 Zeichen)</label>
              <textarea id="extend-reason" rows="2" (input)="extendReason.set($any($event.target).value)"></textarea>
              <button type="button" id="extend-submit" class="btn-primary" [disabled]="!extendValid() || busy()" (click)="extend()">
                Verlängern
              </button>
            </div>
          }

          @if (f.summary_de || f.reachability) {
            <div class="plan-block">
              <div class="plan-block-title">
                <span>Claude-Einschätzung (Empfehlung)</span>
                <span>{{ f.complexity === 'SIMPLE' ? 'Einfacher Fix' : 'Komplexer Eingriff' }}</span>
              </div>
              @if (f.reachability) {
                <div class="plan-item">
                  <span>Erreichbarkeit: {{ f.reachability }}</span>
                  @if (f.confidence !== null) {
                    <span>{{ (f.confidence * 100).toFixed(0) }} %</span>
                  }
                </div>
              }
              @if (f.summary_de) {
                <p class="detail-text">{{ f.summary_de }}</p>
              }
              @if (f.breaking_changes_de) {
                <p class="detail-text"><strong>Breaking Changes:</strong> {{ f.breaking_changes_de }}</p>
              }
              @for (file of f.affected_files; track file) {
                <div class="plan-item"><code>{{ file }}</code></div>
              }
            </div>
          } @else if (f.triage_status === 'UNTRIAGED') {
            <p class="plan-check-note">Noch keine KI-Einschätzung – das Finding gilt als relevant.</p>
          }

          @if (f.pr; as pr) {
            <div class="plan-block">
              <div class="plan-block-title"><span>Pull Request</span><span>CI: {{ pr.ci_status || '–' }}</span></div>
              <div class="plan-item">
                <a [href]="pr.url" target="_blank" rel="noopener">PR #{{ pr.number }}</a>
                <span class="pr-badge">{{ prLabel(pr.source, pr.draft) }}</span>
              </div>
            </div>
          }

          @if (f.needs_deployment_decision) {
            <div class="plan-block deployment-hint">
              Für dieses Repository ist unbekannt, wie es deployt wird.
              <a href="/projects">Deployment-Art festlegen</a>
            </div>
          }

          @if (f.verification.length > 0) {
            <div class="plan-block">
              <div class="plan-block-title"><span>Live-Verifikation</span><span>{{ f.verification.length }} Container</span></div>
              @for (row of f.verification; track row.host + row.container) {
                <div class="plan-item verification-row">
                  <div>
                    <strong>{{ row.host }}</strong> · {{ row.container }}
                    @if (row.image_created_at) {
                      <span class="plan-item-sub">
                        Hinweis: Image gebaut am {{ fmt(row.image_created_at) }}@if (row.pr_merged_at) {, PR gemergt am {{ fmt(row.pr_merged_at) }}} – kein Beweis
                      </span>
                    }
                  </div>
                  <span class="proof-badge" [attr.data-proof]="row.proof ?? 'none'">{{ proofLabel(row) }}</span>
                </div>
              }
            </div>
          }

          @if (f.manual_runbook) {
            <div class="plan-block">
              <div class="plan-block-title"><span>Manuelles Runbook</span></div>
              <pre class="runbook">{{ f.manual_runbook }}</pre>
            </div>
          }

          <div class="plan-block">
            <div class="plan-block-title"><span>Verlauf</span></div>
            <ol class="events">
              @for (e of f.events; track $index) {
                <li class="event">
                  <span class="plan-item-sub">{{ fmt(e.at) }} · {{ e.actor?.name ?? 'System' }} · {{ sourceLabel(e.source) }}</span>
                  <span>{{ e.from_state ? stateLabel(e.from_state) + ' → ' : '' }}{{ stateLabel(e.to_state) }}</span>
                  @if (e.note) {
                    <span class="plan-item-sub">{{ e.note }}</span>
                  }
                </li>
              }
            </ol>
          </div>
        } @else if (loadError()) {
          <p class="action-error load-error" role="alert">{{ loadError() }}</p>
        } @else {
          <div class="plan-meta">Lade Details…</div>
        }
      </div>
    </div>
  `,
})
export class FindingDetail {
  private readonly api = inject(PatchbotApi);
  readonly findingId = input.required<number>();
  readonly changed = output<FindingDetailDto>();

  readonly detail = signal<FindingDetailDto | null>(null);
  readonly subline = findingSubline;
  readonly busy = signal(false);
  readonly error = signal('');
  readonly loadError = signal('');
  readonly dismissOpen = signal(false);
  readonly dismissChoice = signal<DismissChoice>('DISMISSED');
  readonly dismissReason = signal('');
  readonly extendOpen = signal(false);
  readonly extendReason = signal('');

  readonly isOpen = computed(() => OPEN_STATES.includes(this.detail()?.state ?? ''));
  readonly canReopen = computed(() => REOPENABLE.includes(this.detail()?.state ?? ''));
  readonly dismissValid = computed(() => this.dismissReason().trim().length >= MIN_REASON);
  readonly extendValid = computed(() => this.extendReason().trim().length >= MIN_REASON);
  private action: Subscription | null = null;

  constructor() {
    effect((onCleanup) => {
      const id = this.findingId();
      this.detail.set(null);
      this.loadError.set('');
      this.resetForms();
      const load = this.api.getFinding(id).subscribe({
        next: (d) => this.detail.set(d),
        error: (err: HttpErrorResponse) =>
          this.loadError.set(apiErrorText(err, 'Details konnten nicht geladen werden. Bitte erneut versuchen.')),
      });
      // A newer selection supersedes the pending load and any in-flight action of the previous finding.
      onCleanup(() => {
        load.unsubscribe();
        this.action?.unsubscribe();
        this.action = null;
        this.busy.set(false);
      });
    });
  }

  stateLabel(state: string): string {
    return STATE_LABELS[state] ?? state;
  }

  sourceLabel(source: string): string {
    return SOURCE_LABELS[source] ?? source;
  }

  proofLabel(row: VerificationRowDto): string {
    if (!row.fresh) return 'Telemetrie veraltet';
    return row.proof ? PROOF_LABELS[row.proof] : 'offen';
  }

  prLabel(source: string, draft: boolean): string {
    const base = source === 'BOT' ? 'Renovate/Dependabot' : source === 'PATCHBOT_AI' ? 'KI-Draft' : 'Patchbot';
    return draft ? `${base} · Draft` : base;
  }

  fmt(value: string | null | undefined): string {
    return value ? DATE_FMT.format(new Date(value)) : '';
  }

  acknowledge(): void {
    this.run(this.api.acknowledgeFinding(this.findingId()));
  }

  reopenFinding(): void {
    this.run(this.api.reopenFinding(this.findingId()));
  }

  dismiss(): void {
    const choice = this.dismissChoice();
    const payload: DismissPayload =
      choice === 'DISMISSED'
        ? { mode: 'DISMISSED', reason: this.dismissReason().trim() }
        : { mode: 'SNOOZED', reason: this.dismissReason().trim(), snooze_days: choice === 'SNOOZED_30' ? 30 : 14 };
    this.run(this.api.dismissFinding(this.findingId(), payload));
  }

  extend(): void {
    this.run(this.api.extendFinding(this.findingId(), this.extendReason().trim()));
  }

  private resetForms(): void {
    this.error.set('');
    this.dismissOpen.set(false);
    this.dismissReason.set('');
    this.dismissChoice.set('DISMISSED');
    this.extendOpen.set(false);
    this.extendReason.set('');
  }

  private run(request: Observable<FindingDetailDto>): void {
    this.busy.set(true);
    this.error.set('');
    this.action?.unsubscribe();
    this.action = request.subscribe({
      next: (d) => {
        this.busy.set(false);
        this.detail.set(d);
        this.resetForms();
        this.changed.emit(d);
      },
      error: (err: HttpErrorResponse) => {
        this.busy.set(false);
        this.error.set(apiErrorText(err, 'Aktion fehlgeschlagen. Bitte erneut versuchen.'));
      },
    });
  }
}
