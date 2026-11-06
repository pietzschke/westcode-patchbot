import { Component, computed, input } from '@angular/core';
import { AmpelDto } from '../core/patchbot-api';

const SUBLINES: Record<string, string> = {
  RED: 'Neue, nicht zugewiesene oder überfällige Sicherheits-Aufgaben warten.',
  YELLOW: 'Alle offenen Aufgaben sind übernommen und in der Frist.',
  GREEN: 'Keine offenen Sicherheits-Aufgaben – alle Fixes sind live verifiziert.',
  GREY: 'Patchbot kann den Zustand gerade nicht vollständig bestätigen.',
};

@Component({
  selector: 'app-ampel-banner',
  standalone: true,
  template: `
    <section [class]="'ampel ampel--' + ampel().color.toLowerCase()" role="status" aria-live="polite">
      <span class="ampel-light" aria-hidden="true"></span>
      <div class="ampel-body">
        <div class="ampel-label">{{ ampel().label_de }}</div>
        <div class="ampel-sub">{{ subline() }}</div>
        @if (ampel().causes.length > 0) {
          <ul class="ampel-causes">
            @for (cause of ampel().causes; track $index) {
              <li>{{ cause.text }}</li>
            }
          </ul>
          @if (ampel().findings_color !== 'GREEN') {
            <div class="ampel-sub">
              Zusätzlich gibt es offene Aufgaben ({{ ampel().findings_color === 'RED' ? 'Handlungsbedarf' : 'in Bearbeitung' }}).
            </div>
          }
        }
      </div>
      <dl class="ampel-counts">
        <div><dt>Neu</dt><dd>{{ ampel().counts['new'] ?? 0 }}</dd></div>
        <div><dt>In Arbeit</dt><dd>{{ ampel().counts['in_progress'] ?? 0 }}</dd></div>
        <div><dt>Wartet auf Live</dt><dd>{{ ampel().counts['waiting_live'] ?? 0 }}</dd></div>
        <div><dt>Überfällig</dt><dd>{{ ampel().counts['overdue'] ?? 0 }}</dd></div>
      </dl>
    </section>
  `,
})
export class AmpelBanner {
  readonly ampel = input.required<AmpelDto>();
  readonly subline = computed(() => SUBLINES[this.ampel().color] ?? '');
}
