import { Component, inject, signal } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { PatchbotApi } from './core/patchbot-api';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <header class="shell-bar">
      <div class="brand">
        <span class="brand-mark">W</span>
        <span class="brand-name">Westcode</span>
        <span class="brand-sep"></span>
        <span style="color:var(--neutral-600);">Patchbot</span>
      </div>
      <nav class="nav-links" aria-label="Bereiche">
        <a
          class="nav-link"
          routerLink="/"
          routerLinkActive="active"
          [routerLinkActiveOptions]="{ exact: true }"
        >
          Nach Dienst
        </a>
        <a class="nav-link" routerLink="/hosts" routerLinkActive="active">
          Nach Host (23)
        </a>
        <a class="nav-link" routerLink="/rollouts" routerLinkActive="active">
          Rollout-Historie
        </a>
      </nav>
      <div class="fleet-health" style="display:flex;align-items:center;gap:12px;">
        <span class="dot ok"></span>
        <span>{{ syncStatusText() }}</span>
        <button
          type="button"
          class="btn-secondary btn-standard"
          style="width:auto;margin:0;padding:6px 12px;font-size:12px;"
          [disabled]="isSyncing()"
          (click)="runSync()"
        >
          {{ isSyncing() ? 'Synchronisiere GitHub & Trivy…' : 'Jetzt synchronisieren' }}
        </button>
      </div>
    </header>
    <router-outlet />
  `,
})
export class App {
  private readonly api = inject(PatchbotApi);
  readonly isSyncing = signal<boolean>(false);
  readonly syncStatusText = signal<string>('23 Hosts · GitHub & Trivy gekoppelt');

  runSync(): void {
    this.isSyncing.set(true);
    this.api.triggerLiveSync().subscribe({
      next: (res) => {
        this.isSyncing.set(false);
        this.syncStatusText.set(
          `${res.hosts_count} Hosts · ${res.services_count} Dienste · ${res.prs_count} PRs · ${res.vulns_count} CVEs`,
        );
      },
      error: () => {
        this.isSyncing.set(false);
        this.syncStatusText.set('Synchronisation fehlgeschlagen');
      },
    });
  }
}
