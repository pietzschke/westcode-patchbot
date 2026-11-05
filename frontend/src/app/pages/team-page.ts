import { Component, OnInit, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { AuthService } from '../core/auth';
import { PatchbotApi, TeamMemberDto } from '../core/patchbot-api';

const LAYERS = [
  { value: 'infrastructure', label: 'Infrastruktur' },
  { value: 'application', label: 'Anwendung' },
];
const EMAIL_PATTERN = /^[^@\s]+@westcode\.de$/;

interface MemberDraft {
  id: number | null;
  name: string;
  email: string;
  github_username: string;
  slack_user_id: string;
  layers: string[];
  is_admin: boolean;
  is_default_infra_owner: boolean;
  is_active: boolean;
}

type DraftFlag = 'is_admin' | 'is_default_infra_owner' | 'is_active';
type DraftText = 'name' | 'email' | 'github_username' | 'slack_user_id';

/** Flattens the `detail` of a DRF error response (string, list or field → messages map). */
export function apiErrorText(err: HttpErrorResponse, fallback: string): string {
  const detail: unknown = err.error?.detail;
  if (typeof detail === 'string' && detail) {
    return detail;
  }
  if (Array.isArray(detail) && detail.length) {
    return detail.join(' ');
  }
  if (detail && typeof detail === 'object') {
    const messages = Object.values(detail as Record<string, unknown>).flatMap((v) => (Array.isArray(v) ? v : [v]));
    if (messages.length) {
      return messages.join(' ');
    }
  }
  return fallback;
}

@Component({
  selector: 'app-team-page',
  standalone: true,
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1 class="page-title">Team ({{ members().length }})</h1>
          <p class="page-sub">
            Zuordnung E-Mail ↔ GitHub ↔ Slack ↔ Ebenen. Daraus leitet der Patchbot Zuständigkeiten und Slack-DMs ab.
          </p>
        </div>
        @if (auth.isAdmin()) {
          <button type="button" id="add-member-btn" class="btn-secondary btn-standard" style="width:auto;" (click)="startCreate()">
            Mitglied hinzufügen
          </button>
        }
      </div>
      @if (notice()) {
        <p class="plan-check-note">{{ notice() }}</p>
      }

      @if (auth.isAdmin() && draft(); as d) {
        <section class="group-section member-form">
          <div class="group-head">
            <span class="group-name">{{ d.id === null ? 'Neues Teammitglied' : 'Teammitglied bearbeiten' }}</span>
          </div>
          <div class="member-form-grid">
            <label>Name<input name="name" type="text" [value]="d.name" (input)="setText('name', $any($event.target).value)" /></label>
            <label>
              E-Mail (&#64;westcode.de)
              <input name="email" type="email" [value]="d.email" (input)="setText('email', $any($event.target).value)" />
            </label>
            <label>
              GitHub-Benutzer
              <input name="github_username" type="text" [value]="d.github_username"
                (input)="setText('github_username', $any($event.target).value)" />
            </label>
            <label>
              Slack-User-ID
              <input name="slack_user_id" type="text" [value]="d.slack_user_id" placeholder="automatisch per E-Mail"
                (input)="setText('slack_user_id', $any($event.target).value)" />
            </label>
          </div>
          <div class="member-form-flags">
            @for (layer of layers; track layer.value) {
              <label class="toggle">
                <input type="checkbox" [name]="'layer-' + layer.value" [checked]="d.layers.includes(layer.value)"
                  (change)="setLayer(layer.value, $any($event.target).checked)" />
                {{ layer.label }}
              </label>
            }
            <label class="toggle">
              <input type="checkbox" name="is_admin" [checked]="d.is_admin" (change)="setFlag('is_admin', $any($event.target).checked)" />
              Admin
            </label>
            <label class="toggle">
              <input type="checkbox" name="is_default_infra_owner" [checked]="d.is_default_infra_owner"
                (change)="setFlag('is_default_infra_owner', $any($event.target).checked)" />
              Standard-Infra-Owner
            </label>
            <label class="toggle">
              <input type="checkbox" name="is_active" [checked]="d.is_active" (change)="setFlag('is_active', $any($event.target).checked)" />
              aktiv
            </label>
          </div>
          @if (formError()) {
            <p class="action-error">{{ formError() }}</p>
          }
          <div class="action-links">
            <button type="button" class="btn-link save-btn" [disabled]="saving()" (click)="save()">Speichern</button>
            <button type="button" class="btn-link" (click)="cancel()">Abbrechen</button>
          </div>
        </section>
      }

      <table class="host-table team-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>E-Mail</th>
            <th>GitHub</th>
            <th>Slack</th>
            <th>Ebenen</th>
            <th>Rollen</th>
            @if (auth.isAdmin()) {
              <th></th>
            }
          </tr>
        </thead>
        <tbody>
          @for (m of members(); track m.id) {
            <tr class="team-row" [class.inactive]="!m.is_active">
              <td><strong>{{ m.name }}</strong></td>
              <td>{{ m.email }}</td>
              <td>{{ m.github_username ?? '—' }}</td>
              <td>{{ m.slack_user_id ?? '—' }}</td>
              <td>{{ layerLabels(m) }}</td>
              <td>
                @if (m.is_admin) {
                  <span class="type-badge">Admin</span>
                }
                @if (m.is_default_infra_owner) {
                  <span class="type-badge">Infra-Owner</span>
                }
                @if (!m.is_active) {
                  <span class="type-badge">inaktiv</span>
                }
              </td>
              @if (auth.isAdmin()) {
                <td class="team-actions">
                  <button type="button" class="btn-link edit-btn" (click)="startEdit(m)">Bearbeiten</button>
                  <button type="button" class="btn-link test-dm-btn" (click)="testDm(m)">Test-DM senden</button>
                </td>
              }
            </tr>
          } @empty {
            <tr><td colspan="7" class="empty-state">Noch keine Teammitglieder angelegt.</td></tr>
          }
        </tbody>
      </table>
    </main>
  `,
})
export class TeamPage implements OnInit {
  private readonly api = inject(PatchbotApi);
  readonly auth = inject(AuthService);
  readonly layers = LAYERS;

  readonly members = signal<TeamMemberDto[]>([]);
  readonly draft = signal<MemberDraft | null>(null);
  readonly formError = signal('');
  readonly notice = signal('');
  readonly saving = signal(false);

  ngOnInit(): void {
    this.reload();
  }

  reload(): void {
    this.api.listTeam().subscribe((items) => this.members.set(items));
  }

  layerLabels(m: TeamMemberDto): string {
    return LAYERS.filter((l) => m.layers.includes(l.value)).map((l) => l.label).join(', ') || '—';
  }

  startCreate(): void {
    this.formError.set('');
    this.draft.set({
      id: null, name: '', email: '', github_username: '', slack_user_id: '', layers: [],
      is_admin: false, is_default_infra_owner: false, is_active: true,
    });
  }

  startEdit(m: TeamMemberDto): void {
    this.formError.set('');
    this.draft.set({
      id: m.id, name: m.name, email: m.email, github_username: m.github_username ?? '',
      slack_user_id: m.slack_user_id ?? '', layers: [...m.layers], is_admin: m.is_admin,
      is_default_infra_owner: m.is_default_infra_owner, is_active: m.is_active,
    });
  }

  cancel(): void {
    this.draft.set(null);
    this.formError.set('');
  }

  setText(field: DraftText, value: string): void {
    this.draft.update((d) => (d ? { ...d, [field]: value } : d));
  }

  setFlag(field: DraftFlag, value: boolean): void {
    this.draft.update((d) => (d ? { ...d, [field]: value } : d));
  }

  setLayer(layer: string, enabled: boolean): void {
    this.draft.update((d) => {
      if (!d) {
        return d;
      }
      const selected = new Set(d.layers);
      if (enabled) {
        selected.add(layer);
      } else {
        selected.delete(layer);
      }
      return { ...d, layers: LAYERS.map((l) => l.value).filter((v) => selected.has(v)) };
    });
  }

  save(): void {
    const d = this.draft();
    if (!d) {
      return;
    }
    const name = d.name.trim();
    const email = d.email.trim().toLowerCase();
    if (!name) {
      this.formError.set('Bitte einen Namen angeben.');
      return;
    }
    if (!EMAIL_PATTERN.test(email)) {
      this.formError.set('Nur @westcode.de-Adressen sind erlaubt.');
      return;
    }
    const payload: Partial<TeamMemberDto> = {
      name,
      email,
      github_username: d.github_username.trim() || null,
      slack_user_id: d.slack_user_id.trim() || null,
      layers: d.layers,
      is_admin: d.is_admin,
      is_default_infra_owner: d.is_default_infra_owner,
      is_active: d.is_active,
    };
    const request = d.id === null ? this.api.createTeamMember(payload) : this.api.updateTeamMember(d.id, payload);
    this.saving.set(true);
    this.formError.set('');
    request.subscribe({
      next: (saved) => {
        this.saving.set(false);
        this.draft.set(null);
        this.notice.set(`${saved.name} gespeichert.`);
        this.reload();
      },
      error: (err: HttpErrorResponse) => {
        this.saving.set(false);
        this.formError.set(apiErrorText(err, 'Speichern fehlgeschlagen.'));
      },
    });
  }

  testDm(m: TeamMemberDto): void {
    this.api.sendTestDm(m.id).subscribe({
      next: () => this.notice.set(`Test-DM an ${m.name} angestoßen.`),
      error: (err: HttpErrorResponse) => this.notice.set(apiErrorText(err, 'Test-DM konnte nicht gesendet werden.')),
    });
  }
}
