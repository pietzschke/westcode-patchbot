import { Component, OnInit, inject, signal } from '@angular/core';
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
            Paket-/Container-Updates.
          </p>
        </div>
      </div>

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
            <tr class="host-row">
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
    </main>
  `,
})
export class HostsPage implements OnInit {
  private readonly api = inject(PatchbotApi);
  readonly hosts = signal<HostDto[]>([]);

  ngOnInit(): void {
    this.api.listHosts().subscribe((items) => {
      this.hosts.set(items);
    });
  }
}
