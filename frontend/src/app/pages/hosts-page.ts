import { Component, OnInit, computed, effect, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { AuthService } from '../core/auth';
import { HostContainerDto, HostDto, PatchbotApi } from '../core/patchbot-api';

const MINUTE = 60_000;
/** Spec §4.2: telemetry is fresh while the agent reported within the last 60 minutes. */
const TELEMETRY_MAX_AGE_MIN = 60;
/** apt lists older than 26 h mean the daily `apt-get update` did not run. */
const APT_LISTS_MAX_AGE_MIN = 26 * 60;

const DATE_FMT = new Intl.DateTimeFormat('de-DE', {
  day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Berlin',
});
const DAY_FMT = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: 'UTC' });

function olderThan(iso: string | null | undefined, minutes: number): boolean {
  if (!iso) {
    return true;
  }
  const at = Date.parse(iso);
  return Number.isNaN(at) || Date.now() - at > minutes * MINUTE;
}

@Component({
  selector: 'app-hosts-page',
  standalone: true,
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1 class="page-title">Live-Hosts ({{ hosts().length }})</h1>
          <p class="page-sub">
            Vom Read-Only-Agenten gemeldete Telemetrie: Kernel, Neustart-Bedarf, offene apt-Updates und laufende
            Container. Der Patchbot hat keinen SSH-Zugriff – Wartung läuft manuell über die angezeigten Befehle.
          </p>
        </div>
      </div>

      <div class="workspace">
        <div>
          <table class="host-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Projekt</th>
                <th>Betriebssystem</th>
                <th>Container</th>
                <th>Offene apt-Updates</th>
              </tr>
            </thead>
            <tbody>
              @for (host of hosts(); track host.hostname) {
                <tr
                  class="host-row"
                  [attr.data-host]="host.slug"
                  [class.selected]="selectedHost()?.hostname === host.hostname"
                  (click)="selectHost(host)"
                >
                  <td>
                    <strong>{{ host.hostname }}</strong>
                    <div class="host-badges">
                      @if (telemetryStale(host)) {
                        <span class="sev-badge badge-telemetry-stale" data-sev="HIGH">Telemetrie veraltet</span>
                      }
                      @if (aptListsStale(host)) {
                        <span class="sev-badge badge-apt-stale" data-sev="MEDIUM">apt-Listen veraltet</span>
                      }
                    </div>
                  </td>
                  <td>{{ host.project?.name ?? '—' }}</td>
                  <td>
                    {{ osLabel(host) }}
                    @if (host.is_os_eol || host.is_eol) {
                      <span class="badge-eol">EOL</span>
                    }
                  </td>
                  <td>{{ host.container_count ?? host.containers_count ?? 0 }}</td>
                  <td>
                    {{ host.pending_apt_count ?? host.actionable_packages_count ?? 0 }}
                    @if (host.security_apt_count) {
                      <span class="finding-sub">({{ host.security_apt_count }} Security)</span>
                    }
                  </td>
                </tr>
              } @empty {
                <tr><td colspan="5" class="empty-state">Noch keine Hosts gemeldet.</td></tr>
              }
            </tbody>
          </table>
        </div>

        @if (selectedHost(); as host) {
          <aside class="plan-stripe-wrap plan-card detail-col" [class.crit]="host.is_os_eol || host.is_eol">
            <div class="plan-panel">
              <div class="plan-header">
                <div class="plan-header-text">
                  <span class="plan-kicker" [class.crit]="host.is_os_eol || host.is_eol">
                    {{ host.provider.toUpperCase() }} · {{ host.stack_name ?? host.stack ?? 'Stack' }}
                  </span>
                  <div class="plan-title">{{ host.hostname }}</div>
                  <div class="plan-meta">
                    @if (telemetryStale(host)) {
                      <span class="crit">Telemetrie veraltet</span>
                    } @else {
                      <span style="color:var(--success);font-weight:600;">Live verbunden</span>
                    }
                    · zuletzt gemeldet {{ fmt(host.last_seen_at) }}
                  </div>
                </div>
              </div>

              <div class="plan-block">
                <div class="plan-block-title"><span>Telemetrie</span></div>
                <dl class="host-facts">
                  <dt>Betriebssystem</dt>
                  <dd>
                    {{ osLabel(host) }}
                    @if (host.os_eol_date) {
                      <span [class.crit]="host.is_os_eol || host.is_eol">· EOL {{ fmtDay(host.os_eol_date) }}</span>
                    }
                  </dd>
                  <dt>Kernel</dt>
                  <dd>
                    {{ host.kernel_version || '—' }}
                    @if (host.reboot_required) {
                      <span class="sev-badge" data-sev="HIGH">Neustart erforderlich</span>
                    }
                  </dd>
                  <dt>apt-Listen</dt>
                  <dd [class.crit]="aptListsStale(host)">{{ fmt(host.apt_lists_updated_at) }}</dd>
                  <dt>Pakete</dt>
                  <dd>{{ host.installed_package_count ?? 0 }} installiert · {{ host.pending_apt_count ?? 0 }} aktualisierbar</dd>
                  <dt>Agent</dt>
                  <dd>{{ host.agent_version || '—' }} · {{ host.has_agent_token ? 'Token aktiv' : 'kein Token' }}</dd>
                </dl>
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>Laufende Container</span>
                  <span>{{ host.containers?.length ?? 0 }}</span>
                </div>
                @for (c of host.containers ?? []; track c.name) {
                  <div class="plan-item container-row">
                    <div>
                      <strong>{{ c.name }}</strong>
                      <span class="plan-item-sub mono">{{ c.image_tag }}</span>
                      <span class="plan-item-sub mono">Digest: {{ digest(c) }}</span>
                      <span class="plan-item-sub mono">Revision: {{ c.oci_revision || '—' }}</span>
                      @if (c.image_created_at) {
                        <span class="plan-item-sub image-built">
                          Image gebaut am {{ fmt(c.image_created_at) }} (Hinweis, kein Live-Beweis)
                        </span>
                      }
                      <span class="plan-item-sub git-state">{{ gitState(c) }}</span>
                    </div>
                    <span class="finding-sub">{{ c.status }}</span>
                  </div>
                } @empty {
                  <div class="plan-item">
                    <span class="plan-item-sub">Keine Container gemeldet.</span>
                  </div>
                }
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>Offene apt-Updates</span>
                  <span>{{ host.packages?.length ?? 0 }} · {{ host.security_apt_count ?? 0 }} Security</span>
                </div>
                @for (p of sortedPackages(host); track p.name) {
                  <div class="plan-item package-row">
                    <div>
                      <strong>{{ p.name }}</strong>
                      @if (p.is_security_update) {
                        <span class="sev-badge" data-sev="HIGH">Security</span>
                      }
                      @if (p.source_pocket) {
                        <span class="plan-item-sub">{{ p.source_pocket }}</span>
                      }
                    </div>
                    <span class="mono">{{ p.installed_version }} → <strong>{{ p.candidate_version }}</strong></span>
                  </div>
                } @empty {
                  <div class="plan-item">
                    <span class="plan-item-sub">Keine offenen apt-Updates gemeldet.</span>
                  </div>
                }
              </div>

              <div class="plan-block">
                <div class="plan-block-title"><span>Manuelle Wartung</span></div>
                <pre class="runbook"><code>ssh root&#64;{{ host.hostname }} "apt-get update &amp;&amp; DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y"</code></pre>

                @if (auth.isAdmin()) {
                  <button type="button" id="agent-token-btn" class="btn-secondary btn-standard" (click)="generateToken(host)">
                    Agent-Token {{ host.has_agent_token ? 'neu ' : '' }}generieren
                  </button>
                  @if (installCommand()) {
                    <p class="plan-check-note">
                      Einmalig angezeigt – auf {{ host.hostname }} im Patchbot-Checkout ausführen. Ein bestehender
                      Token wird damit ungültig.
                    </p>
                    <pre class="runbook install-command"><code>{{ installCommand() }}</code></pre>
                  }
                  @if (tokenError()) {
                    <p class="action-error">{{ tokenError() }}</p>
                  }
                }
              </div>
            </div>
          </aside>
        }
      </div>
    </main>
  `,
})
export class HostsPage implements OnInit {
  private readonly api = inject(PatchbotApi);
  readonly auth = inject(AuthService);

  readonly hosts = signal<HostDto[]>([]);
  readonly selectedHostname = signal<string>('');
  /** Install command with the raw token; only kept until another host is selected. */
  readonly installCommand = signal<string>('');
  readonly tokenError = signal<string>('');

  readonly selectedHost = computed<HostDto | null>(() => {
    const list = this.hosts();
    const name = this.selectedHostname();
    return list.find((h) => h.hostname === name) ?? list[0] ?? null;
  });

  constructor() {
    effect(() => {
      if (this.api.refreshTick() > 0) {
        this.loadHosts();
      }
    });
  }

  ngOnInit(): void {
    this.loadHosts();
  }

  loadHosts(): void {
    this.api.listHosts().subscribe((items) => this.hosts.set(items));
  }

  selectHost(host: HostDto): void {
    if (host.hostname !== this.selectedHostname()) {
      this.installCommand.set('');
      this.tokenError.set('');
    }
    this.selectedHostname.set(host.hostname);
  }

  telemetryStale(host: HostDto): boolean {
    return olderThan(host.last_seen_at, TELEMETRY_MAX_AGE_MIN);
  }

  aptListsStale(host: HostDto): boolean {
    // Never reported apt lists are already covered by the telemetry badge.
    return !!host.apt_lists_updated_at && olderThan(host.apt_lists_updated_at, APT_LISTS_MAX_AGE_MIN);
  }

  osLabel(host: HostDto): string {
    return `${host.os_distro ?? ''} ${host.os_version ?? ''}`.trim() || host.distro || host.declared_image || 'unbekannt';
  }

  sortedPackages(host: HostDto) {
    return [...(host.packages ?? [])].sort(
      (a, b) => Number(b.is_security_update) - Number(a.is_security_update) || a.name.localeCompare(b.name),
    );
  }

  digest(c: HostContainerDto): string {
    const raw = c.repo_digests?.[0];
    if (!raw) {
      return '—';
    }
    const hash = raw.includes('@') ? raw.slice(raw.indexOf('@') + 1) : raw;
    return hash.length > 19 ? `${hash.slice(0, 19)}…` : hash;
  }

  gitState(c: HostContainerDto): string {
    if (!c.git_head_sha && c.git_clean == null) {
      return 'Git: kein Checkout gemeldet';
    }
    const head = c.git_head_sha ? `HEAD ${c.git_head_sha.slice(0, 7)}` : 'HEAD unbekannt';
    const state = c.git_clean == null ? 'Status unbekannt' : c.git_clean ? 'clean' : 'dirty';
    return `Git: ${head} · ${state}${c.working_dir ? ` · ${c.working_dir}` : ''}`;
  }

  fmt(iso: string | null | undefined): string {
    return iso ? DATE_FMT.format(new Date(iso)) : 'nie';
  }

  fmtDay(isoDate: string): string {
    return DAY_FMT.format(new Date(`${isoDate}T00:00:00Z`));
  }

  generateToken(host: HostDto): void {
    const slug = host.slug || host.hostname;
    this.tokenError.set('');
    this.api.generateHostToken(slug).subscribe({
      next: (res) => {
        this.installCommand.set(res.install_command);
        this.hosts.update((list) => list.map((h) => (h.hostname === host.hostname ? res.host : h)));
      },
      error: (err: HttpErrorResponse) =>
        this.tokenError.set(err.status === 403 ? 'Nur Admins dürfen Agent-Tokens erzeugen.' : 'Token konnte nicht erzeugt werden.'),
    });
  }
}
