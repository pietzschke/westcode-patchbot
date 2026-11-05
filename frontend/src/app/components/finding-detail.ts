import { Component, effect, inject, input, output, signal } from '@angular/core';
import { FindingDetailDto, PatchbotApi } from '../core/patchbot-api';

@Component({
  selector: 'app-finding-detail',
  standalone: true,
  template: `
    <div class="plan-card" [class.crit]="detail()?.highest_severity === 'CRITICAL'">
      <div class="plan-panel">
        @if (detail(); as f) {
          <h2 class="plan-title" id="detail-title">{{ f.title }}</h2>
          <div class="plan-meta">{{ f.project.name }} · {{ f.vulnerability_ids.join(', ') }}</div>
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

  constructor() {
    effect(() => {
      const id = this.findingId();
      this.detail.set(null);
      this.api.getFinding(id).subscribe((d) => this.detail.set(d));
    });
  }
}
