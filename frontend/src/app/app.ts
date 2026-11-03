import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

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
        <button type="button" class="nav-link">
          Rollout-Historie
        </button>
      </nav>
      <div class="fleet-health">
        <span class="dot ok"></span>
        <span>23 Hosts synchron · Letzter Lauf vor 4 Min.</span>
      </div>
    </header>
    <router-outlet />
  `,
})
export class App {}
