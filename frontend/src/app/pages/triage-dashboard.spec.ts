import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TriageDashboard } from './triage-dashboard';
import { AmpelBanner } from '../components/ampel-banner';
import { AmpelDto, DashboardDto, FindingDto } from '../core/patchbot-api';

function finding(over: Partial<FindingDto>): FindingDto {
  return {
    id: 1, title: 'lodash 4.17.21', project: { slug: 'wuerth', name: 'Würth' }, layer: 'APPLICATION',
    target_ref: 'repo:westcoder/mdb', package_name: 'lodash', current_version: '4.17.15', target_version: '4.17.21',
    vulnerability_ids: ['CVE-2026-0001'], highest_severity: 'HIGH', kev_listed: false, state: 'NEW',
    complexity: 'SIMPLE', triage_status: 'TRIAGED', assignee: { id: 7, name: 'Moritz' },
    deadline_at: '2026-11-10T07:00:00Z', overdue: false, pr: null, ...over,
  };
}

const DASHBOARD: DashboardDto = {
  ampel: {
    color: 'GREY', label_de: 'Datenlage unvollständig', findings_color: 'RED',
    causes: [{ code: 'agent_stale', text: 'Agent auf mdb.westcode.de seit 75 min stumm.' }],
    counts: { new: 1, in_progress: 1 }, computed_at: '2026-11-09T09:00:00Z',
  },
  buckets: {
    simple: [finding({ id: 1 })],
    complex: [finding({ id: 2, title: 'django 6.0', project: { slug: 'ses', name: 'SES Sandmann' }, complexity: 'COMPLEX',
      state: 'IN_PROGRESS', highest_severity: 'CRITICAL', assignee: { id: 9, name: 'Anna' } })],
    waiting_live: [],
  },
  filtered: [],
  maintenance: [{ id: 5, project: { slug: 'wuerth', name: 'Würth' }, repository: 'westcoder/mdb', package_name: 'eslint',
    current_version: '9.1.0', target_version: '9.2.0', update_type: 'MINOR', pr_number: 42,
    pr_url: 'https://github.com/westcoder/mdb/pull/42', ci_status: 'success', summary_de: '' }],
  me_id: 7,
};

function setup(data: DashboardDto = DASHBOARD) {
  TestBed.configureTestingModule({
    imports: [TriageDashboard],
    providers: [provideHttpClient(), provideHttpClientTesting()],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(TriageDashboard);
  fixture.detectChanges();
  http.expectOne('/api/dashboard/').flush(data);
  fixture.detectChanges();
  return { fixture, el: fixture.nativeElement as HTMLElement };
}

function click(fixture: { detectChanges(): void }, el: HTMLElement, selector: string) {
  el.querySelector<HTMLElement>(selector)!.click();
  fixture.detectChanges();
}

describe('TriageDashboard', () => {
  it('renders the grey Ampel with its causes', () => {
    const { el } = setup();
    expect(el.querySelector('.ampel--grey')?.textContent).toContain('Datenlage unvollständig');
    expect(el.querySelector('.ampel-causes')?.textContent).toContain('mdb.westcode.de');
  });

  it('renders the three buckets with counts', () => {
    const { el } = setup();
    const count = (b: string) => el.querySelectorAll(`[data-bucket="${b}"] .finding-row`).length;
    expect([count('simple'), count('complex'), count('waiting_live')]).toEqual([1, 1, 0]);
    expect(el.querySelector('[data-bucket="complex"] .sev-badge')?.textContent).toContain('CRITICAL');
  });

  it('switches to maintenance updates and to the filtered list', () => {
    const { fixture, el } = setup();
    click(fixture, el, '[data-mode="maintenance"]');
    expect(el.querySelectorAll('.maintenance-row').length).toBe(1);
    expect(el.querySelector('.maintenance-row')?.textContent).toContain('eslint');
    click(fixture, el, '[data-mode="filtered"]');
    expect(el.querySelector('.empty-state')?.textContent).toContain('Keine automatisch gefilterten');
  });

  it('„Nur meine Aufgaben“ hides findings of other assignees', () => {
    const { fixture, el } = setup();
    click(fixture, el, '#only-mine');
    expect(el.querySelectorAll('.finding-row').length).toBe(1);
    expect(el.querySelector('.finding-row')?.textContent).toContain('lodash');
  });

  it('filters by minimum severity', () => {
    const { fixture, el } = setup();
    const select = el.querySelector<HTMLSelectElement>('#severity-filter')!;
    expect(Array.from(select.options).map((o) => o.value)).toEqual(['', 'CRITICAL', 'HIGH', 'MEDIUM']);
    select.value = 'CRITICAL';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    const rows = Array.from(el.querySelectorAll('.finding-row')).map((r) => r.textContent ?? '');
    expect(rows.length).toBe(1);
    expect(rows[0]).toContain('django');
    select.value = 'HIGH';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(el.querySelectorAll('.finding-row').length).toBe(2);
    click(fixture, el, '[data-group="project"]');
    select.value = 'CRITICAL';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    const heads = Array.from(el.querySelectorAll('.group-head .group-name')).map((h) => h.textContent?.trim());
    expect(heads).toEqual(['SES Sandmann']);
  });

  it('groups by project when „Nach Projekt“ is selected', () => {
    const { fixture, el } = setup();
    click(fixture, el, '[data-group="project"]');
    const heads = Array.from(el.querySelectorAll('.group-head .group-name')).map((h) => h.textContent?.trim());
    expect(heads).toEqual(['SES Sandmann', 'Würth']);
  });

  it('shows the host instead of an empty CVE list and keeps the columns aligned', () => {
    const eol = finding({
      id: 3, title: 'Betriebssystem-EOL: Ubuntu 20.04 → 24.04', layer: 'INFRASTRUCTURE',
      target_ref: 'host:shop-prod-01', package_name: '__os_eol__', vulnerability_ids: [],
    });
    const withPr = finding({ id: 4, pr: { number: 12, url: '', draft: true, source: 'PATCHBOT', ci_status: '' } });
    const { el } = setup({ ...DASHBOARD, buckets: { simple: [eol, withPr], complex: [], waiting_live: [] } });
    const rows = el.querySelectorAll('.finding-row');
    expect(rows[0].querySelector('.finding-sub')?.textContent?.trim()).toBe('Würth · shop-prod-01');
    // Every row renders the same four grid cells, so assignee and deadline line up with and without a PR.
    expect(rows[0].children.length).toBe(4);
    expect(rows[1].children.length).toBe(4);
    expect(rows[1].querySelector('.finding-title .pr-badge')?.textContent).toContain('PR #12 · Draft');
  });
  it('selects a finding on row click', () => {
    const { fixture, el } = setup();
    click(fixture, el, '.finding-row');
    expect(el.querySelector('.finding-row.selected')).toBeTruthy();
    TestBed.inject(HttpTestingController).expectOne('/api/findings/1/');
  });
});

describe('AmpelBanner', () => {
  it.each([
    ['RED', 'Handlungsbedarf', 'ampel--red'],
    ['YELLOW', 'In Bearbeitung', 'ampel--yellow'],
    ['GREEN', 'Alles im grünen Bereich', 'ampel--green'],
  ])('renders %s', (color, label, cls) => {
    TestBed.configureTestingModule({ imports: [AmpelBanner] });
    const fixture = TestBed.createComponent(AmpelBanner);
    const ampel: AmpelDto = { color: color as AmpelDto['color'], label_de: label, findings_color: color as AmpelDto['color'],
      causes: [], counts: {}, computed_at: '' };
    fixture.componentRef.setInput('ampel', ampel);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector(`.${cls}`)?.textContent).toContain(label);
    expect(el.querySelector('.ampel-causes')).toBeNull();
  });
});
