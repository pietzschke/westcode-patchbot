import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { FindingDetail } from './finding-detail';
import { FindingDetailDto } from '../core/patchbot-api';

function detail(over: Partial<FindingDetailDto> = {}): FindingDetailDto {
  return {
    id: 1, title: 'lodash 4.17.21', project: { slug: 'wuerth', name: 'Würth' }, layer: 'APPLICATION',
    target_ref: 'repo:westcoder/mdb', package_name: 'lodash', current_version: '4.17.15', target_version: '4.17.21',
    vulnerability_ids: ['CVE-2026-0001'], highest_severity: 'HIGH', kev_listed: false, state: 'NEW',
    complexity: 'SIMPLE', triage_status: 'TRIAGED', assignee: { id: 7, name: 'Moritz' },
    deadline_at: '2026-11-10T07:00:00Z', overdue: false, pr: null,
    reachability: 'REACHABLE', confidence: 0.85, summary_de: 'lodash.template wird in src/report.ts genutzt.',
    breaking_changes_de: '', affected_files: ['src/report.ts:42'], assigned_reason_de: 'Projekt-Owner laut Notion',
    discovered_at: '2026-11-09T06:00:00Z', acknowledged_at: null, pr_merged_at: null, verified_live_at: null,
    extended_in_stage: '', dismissal: null, manual_runbook: '', verification: [], verification_checked_at: null,
    needs_deployment_decision: false, repository_id: 3,
    events: [{ at: '2026-11-09T06:00:00Z', actor: null, source: 'SYSTEM', from_state: '', to_state: 'NEW', note: 'Neu entdeckt.' }],
    ...over,
  };
}

function setup(initial: FindingDetailDto) {
  TestBed.configureTestingModule({
    imports: [FindingDetail],
    providers: [provideHttpClient(), provideHttpClientTesting()],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(FindingDetail);
  fixture.componentRef.setInput('findingId', initial.id);
  fixture.detectChanges();
  http.expectOne(`/api/findings/${initial.id}/`).flush(initial);
  fixture.detectChanges();
  const el: HTMLElement = fixture.nativeElement;
  const type = (selector: string, value: string) => {
    const input = el.querySelector<HTMLTextAreaElement>(selector)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
  };
  const click = (selector: string) => {
    el.querySelector<HTMLElement>(selector)!.click();
    fixture.detectChanges();
  };
  return { fixture, el, http, type, click };
}

describe('FindingDetail', () => {
  it('acknowledges via „Ich bin dran“ and re-renders', () => {
    const { el, http, click, fixture } = setup(detail());
    const emitted: unknown[] = [];
    fixture.componentInstance.changed.subscribe((d) => emitted.push(d));
    expect(el.querySelector('#ack-btn')?.textContent).toContain('Ich bin dran');
    click('#ack-btn');
    const req = http.expectOne('/api/findings/1/acknowledge/');
    expect(req.request.method).toBe('POST');
    req.flush(detail({ state: 'IN_PROGRESS' }));
    fixture.detectChanges();
    expect(el.querySelector('.state-label')?.textContent).toContain('In Bearbeitung');
    expect(emitted.length).toBe(1);
  });

  it('requires a 15-character reason before dismissing', () => {
    const { el, http, click, type } = setup(detail());
    click('#dismiss-open');
    const submit = () => el.querySelector<HTMLButtonElement>('#dismiss-submit')!;
    expect(submit().disabled).toBe(true);
    type('#dismiss-reason', 'zu kurz');
    expect(submit().disabled).toBe(true);
    type('#dismiss-reason', 'Nur im Build-Container genutzt.');
    const mode = el.querySelector<HTMLSelectElement>('#dismiss-mode')!;
    mode.value = 'SNOOZED_30';
    mode.dispatchEvent(new Event('change'));
    expect(submit().disabled).toBe(false);
    click('#dismiss-submit');
    const req = http.expectOne('/api/findings/1/dismiss/');
    expect(req.request.body).toEqual({ mode: 'SNOOZED', reason: 'Nur im Build-Container genutzt.', snooze_days: 30 });
  });

  it('shows verification proofs and treats the build time only as a hint', () => {
    const { el } = setup(detail({
      state: 'PR_MERGED_WAITING_LIVE', pr_merged_at: '2026-11-09T10:00:00Z',
      verification: [
        { host: 'mdb.westcode.de', container: 'app', fresh: true, proof: 'REVISION', image_created_at: null },
        { host: 'converter.westcode.de', container: 'app', fresh: true, proof: null,
          image_created_at: '2026-11-09T10:30:00Z', pr_merged_at: '2026-11-09T10:00:00Z' },
        { host: 'old.westcode.de', container: 'app', fresh: false, proof: null },
      ],
    }));
    const rows = Array.from(el.querySelectorAll('.verification-row')).map((r) => r.textContent ?? '');
    expect(rows[0]).toContain('Revision');
    expect(rows[1]).toContain('offen');
    expect(rows[1]).toContain('Hinweis');
    expect(rows[2]).toContain('Telemetrie veraltet');
  });

  it('asks for a deployment decision when needed', () => {
    const { el } = setup(detail({ state: 'PR_MERGED_WAITING_LIVE', needs_deployment_decision: true }));
    const hint = el.querySelector('.deployment-hint');
    expect(hint?.textContent).toContain('Deployment-Art festlegen');
    expect(hint?.querySelector('a')?.getAttribute('href')).toBe('/projects');
  });

  it('renders the event history', () => {
    const { el } = setup(detail({
      events: [
        { at: '2026-11-09T06:00:00Z', actor: null, source: 'SYSTEM', from_state: '', to_state: 'NEW', note: 'Neu entdeckt.' },
        { at: '2026-11-09T08:00:00Z', actor: { id: 7, name: 'Moritz' }, source: 'SLACK', from_state: 'NEW',
          to_state: 'IN_PROGRESS', note: '„Ich bin dran“' },
      ],
    }));
    const events = Array.from(el.querySelectorAll('.event')).map((e) => e.textContent ?? '');
    expect(events[1]).toContain('Moritz');
    expect(events[1]).toContain('Slack');
    expect(events[0]).toContain('System');
  });

  it('extends once per stage with a reason', () => {
    const { el, http, click, type, fixture } = setup(detail({ state: 'IN_PROGRESS' }));
    click('#extend-open');
    expect(el.querySelector<HTMLButtonElement>('#extend-submit')!.disabled).toBe(true);
    type('#extend-reason', 'Warten auf Upstream-Release 2.4.1');
    click('#extend-submit');
    http.expectOne('/api/findings/1/extend/').flush(detail({ state: 'IN_PROGRESS', extended_in_stage: 'IN_PROGRESS' }));
    fixture.detectChanges();
    expect(el.querySelector('#extend-open')).toBeNull();
  });

  it('shows the API error message', () => {
    const { el, http, click, fixture } = setup(detail({ state: 'NEW' }));
    click('#ack-btn');
    http.expectOne('/api/findings/1/acknowledge/').flush({ detail: 'Kaputt' }, { status: 409, statusText: 'Conflict' });
    fixture.detectChanges();
    expect(el.querySelector('.action-error')?.textContent).toContain('Kaputt');
  });
});
