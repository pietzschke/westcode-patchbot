import { Component, OnInit, computed, effect, inject, signal } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { getLogoSvg } from '../core/logos';
import { HostDto, PatchbotApi } from '../core/patchbot-api';

@Component({
  selector: 'app-hosts-page',
  standalone: true,
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1 class="page-title">Nach Host ({{ hosts().length || 23 }})</h1>
          <p class="page-sub">
            Übersicht der 23 Infrastruktur-Hosts nach Stack, Provider, Betriebssystem und offenen
            Paket-/Container-Updates. Klicke auf einen Host für Details, SSH-Live-Abfrage oder
            Agent-Onboarding.
          </p>
        </div>
      </div>

      <div class="workspace">
        <div>
          <table class="host-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Stack</th>
                <th>Provider</th>
                <th>Distro</th>
                <th>Container</th>
                <th>Offene Pakete</th>
              </tr>
            </thead>
            <tbody>
              @for (host of hosts(); track host.hostname) {
                <tr
                  class="host-row"
                  style="cursor:pointer;"
                  [style.background]="selectedHost()?.hostname === host.hostname ? 'var(--bluefly-50)' : ''"
                  (click)="selectHost(host)"
                >
                  <td><strong>{{ host.hostname }}</strong></td>
                  <td>{{ host.stack_name ?? host.stack ?? '—' }}</td>
                  <td>{{ host.provider }}</td>
                  <td>
                    {{ host.os_distro ?? host.distro ?? '' }} {{ host.os_version ?? '' }}
                    @if (host.is_os_eol || host.is_eol) {
                      <span class="badge-eol">EOL</span>
                    }
                  </td>
                  <td>{{ host.container_count ?? host.containers_count ?? 0 }}</td>
                  <td>{{ host.pending_apt_count ?? host.actionable_packages_count ?? 0 }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>

        @if (selectedHost(); as host) {
          <aside
            class="plan-stripe-wrap plan-card"
            [class.crit]="host.is_os_eol || host.is_eol"
          >
            <div class="plan-panel">
              <div class="plan-header">
                <div
                  class="svc-logo"
                  style="background:#fff;"
                  [innerHTML]="renderLogo('ubuntu', host.hostname)"
                ></div>
                <div class="plan-header-text">
                  <span class="plan-kicker" [class.crit]="host.is_os_eol || host.is_eol">
                    {{ host.provider.toUpperCase() }} · {{ host.stack_name ?? host.stack ?? 'Stack' }}
                  </span>
                  <div class="plan-title">{{ host.hostname }}</div>
                  <div class="plan-meta">
                    {{ host.distro || (host.os_distro + ' ' + host.os_version) || 'OS ausstehend' }}
                    @if (host.is_os_eol || host.is_eol) {
                      · <strong style="color:var(--salmon-700);">End-of-Life (EOL)</strong>
                    }
                    ·
                    @if (host.last_seen_at) {
                      <span style="color:var(--success);font-weight:600;">Live verbunden</span>
                    } @else {
                      <span>Sollzustand aus westcode-infra</span>
                    }
                  </div>
                </div>
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>Host-Anbindung &amp; Inventar-Abruf</span>
                  <span>{{ host.has_agent_token ? 'Token aktiv' : 'Kein Token' }}</span>
                </div>
                <div style="display:flex;gap:8px;margin-top:6px;">
                  <button
                    type="button"
                    class="btn-secondary btn-standard"
                    style="margin:0;flex:1;"
                    [disabled]="isProbing()"
                    (click)="probeHostSsh(host)"
                  >
                    {{ isProbing() ? 'Frage per SSH ab…' : 'Live per SSH abfragen' }}
                  </button>
                  <button
                    type="button"
                    class="btn-secondary btn-standard"
                    style="margin:0;flex:1;"
                    (click)="generateToken(host)"
                  >
                    Agent-Token generieren
                  </button>
                </div>

                @if (probeMessage()) {
                  <div
                    class="plan-item"
                    style="margin-top:8px;"
                    [style.color]="probeError() ? 'var(--salmon-700)' : 'var(--success)'"
                  >
                    <span>{{ probeMessage() }}</span>
                  </div>
                }

                @if (generatedInstallCmd()) {
                  <div style="margin-top:10px;">
                    <div style="font-size:11px;font-weight:700;color:var(--neutral-600);margin-bottom:4px;">
                      Auf {{ host.hostname }} ausführen (Token wird einmalig angezeigt):
                    </div>
                    <pre
                      style="background:var(--neutral-900);color:#fff;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto;margin:0;"
                    ><code>{{ generatedInstallCmd() }}</code></pre>
                  </div>
                }
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>Laufende / zugeordnete Container</span>
                  <span>{{ host.containers?.length ?? host.container_count ?? 0 }} Container</span>
                </div>
                @for (c of host.containers ?? []; track c.name) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ c.name }}</strong>
                      <span class="plan-item-sub" style="display:block;">
                        {{ c.working_dir || '/opt' }} ·
                        {{ c.git_clean !== false ? 'git clean' : 'git dirty' }}
                      </span>
                    </div>
                    <span style="font-family:var(--font-mono);font-size:11px;">
                      {{ c.oci_revision || c.image_tag }}
                    </span>
                  </div>
                } @empty {
                  <div class="plan-item">
                    <span class="plan-item-sub">
                      Noch keine Container erfasst — klicke oben auf „Live per SSH abfragen“ oder
                      kopple den Agenten.
                    </span>
                  </div>
                }
              </div>

              <div class="plan-block">
                <div class="plan-block-title">
                  <span>Ausstehende System-Pakete (apt)</span>
                  <span>{{ host.packages?.length ?? host.pending_apt_count ?? 0 }} Pakete</span>
                </div>
                @for (p of host.packages ?? []; track p.name) {
                  <div class="plan-item">
                    <div>
                      <strong>{{ p.name }}</strong>
                      @if (p.is_security_update) {
                        <span class="badge-eol" style="margin-left:6px;">SECURITY</span>
                      }
                    </div>
                    <span style="font-family:var(--font-mono);font-size:11px;">
                      {{ p.installed_version }} → <strong>{{ p.candidate_version }}</strong>
                    </span>
                  </div>
                } @empty {
                  <div class="plan-item">
                    <span class="plan-item-sub">Keine offenen apt-Paketupdates gemeldet.</span>
                  </div>
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
  private readonly sanitizer = inject(DomSanitizer);

  readonly hosts = signal<HostDto[]>([]);
  readonly selectedHostname = signal<string>('');
  readonly isProbing = signal<boolean>(false);
  readonly probeMessage = signal<string>('');
  readonly probeError = signal<boolean>(false);
  readonly generatedInstallCmd = signal<string>('');

  readonly selectedHost = computed<HostDto | null>(() => {
    const list = this.hosts();
    if (list.length === 0) {
      return null;
    }
    const name = this.selectedHostname();
    return list.find((h) => h.hostname === name) ?? list[0];
  });

  constructor() {
    effect(() => {
      const tick = this.api.refreshTick();
      if (tick > 0) {
        this.loadHosts();
      }
    });
  }

  ngOnInit(): void {
    this.loadHosts();
  }

  loadHosts(): void {
    this.api.listHosts().subscribe((items) => {
      this.hosts.set(items);
      if (items.length > 0 && !this.selectedHostname()) {
        this.selectedHostname.set(items[0].hostname);
      }
    });
  }

  selectHost(host: HostDto): void {
    this.selectedHostname.set(host.hostname);
    this.probeMessage.set('');
    this.generatedInstallCmd.set('');
  }

  renderLogo(key: string, name: string): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(getLogoSvg(key, name));
  }

  generateToken(host: HostDto): void {
    const slug = host.slug || host.hostname;
    this.api.generateHostToken(slug).subscribe((res) => {
      this.generatedInstallCmd.set(res.install_command);
      this.hosts.update((list) =>
        list.map((h) => (h.hostname === host.hostname ? res.host : h)),
      );
    });
  }

  probeHostSsh(host: HostDto): void {
    const slug = host.slug || host.hostname;
    this.isProbing.set(true);
    this.probeMessage.set('');
    this.probeError.set(false);
    this.api.probeHostSsh(slug).subscribe({
      next: (res) => {
        this.isProbing.set(false);
        this.probeError.set(false);
        this.probeMessage.set(res.detail);
        this.hosts.update((list) =>
          list.map((h) => (h.hostname === host.hostname ? res.host : h)),
        );
      },
      error: (err) => {
        this.isProbing.set(false);
        this.probeError.set(true);
        this.probeMessage.set(
          err?.error?.detail || `SSH-Abfrage für ${host.hostname} fehlgeschlagen.`,
        );
      },
    });
  }
}
