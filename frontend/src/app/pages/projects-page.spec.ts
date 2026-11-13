import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ProjectsPage } from './projects-page';
import { AuthService } from '../core/auth';
import { MeDto, TriageProjectsDto } from '../core/patchbot-api';

const DATA: TriageProjectsDto = {
  projects: [
    {
      slug: 'wuerth', name: 'Würth', customer_name: 'Adolf Würth GmbH', is_internal: false, notion_status: 'In progress',
      notion_missing: false, is_monitored: true, owner: { id: 7, name: 'Moritz' }, last_notion_synced_at: null,
      repositories: [{ id: 3, type: 'repository', name: 'westcoder/materialdatenbank', suggested_project: null,
        deployment_mode: 'UNKNOWN' }],
      hosts: [{ id: 4, type: 'host', name: 'mdb.westcode.de', suggested_project: null }],
      containers: [{ id: 5, type: 'container', name: 'mdb.westcode.de: app', image: 'ghcr.io/westcoder/mdb:1.4',
        suggested_project: null }],
      open_findings: 2,
    },
    {
      slug: 'alt', name: 'Altkunde', customer_name: '', is_internal: false, notion_status: 'Done', notion_missing: true,
      is_monitored: false, owner: null, last_notion_synced_at: null, repositories: [], hosts: [], containers: [],
      open_findings: 0,
    },
  ],
  unassigned_assets: {
    repositories: [{ id: 9, type: 'repository', name: 'westcoder/wuerth-converter',
      suggested_project: { slug: 'wuerth', name: 'Würth' }, deployment_mode: 'UNKNOWN' }],
    hosts: [{ id: 10, type: 'host', name: 'lonely.westcode.de', suggested_project: null }],
    containers: [],
  },
};

function me(isAdmin: boolean): MeDto {
  return { id: 7, name: 'Moritz', email: 'm@westcode.de', github_username: null, slack_user_id: 'U1', layers: [],
    is_admin: isAdmin, is_default_infra_owner: false };
}

function setup(isAdmin = true) {
  TestBed.configureTestingModule({
    imports: [ProjectsPage],
    providers: [provideHttpClient(), provideHttpClientTesting()],
  });
  TestBed.inject(AuthService).me.set(me(isAdmin));
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(ProjectsPage);
  fixture.detectChanges();
  http.expectOne('/api/triage-projects/').flush(DATA);
  fixture.detectChanges();
  return { fixture, http, el: fixture.nativeElement as HTMLElement };
}

describe('ProjectsPage', () => {
  it('confirms a suggestion from the unassigned inbox', () => {
    const { fixture, http, el } = setup();
    const rows = el.querySelectorAll('.inbox-row');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('Vorschlag: Würth');
    rows[0].querySelector<HTMLButtonElement>('.confirm-btn')!.click();
    const req = http.expectOne('/api/assets/repository/9/confirm-suggestion/');
    expect(req.request.method).toBe('POST');
    req.flush({});
    http.expectOne('/api/triage-projects/').flush({ ...DATA, unassigned_assets: { ...DATA.unassigned_assets, repositories: [] } });
    fixture.detectChanges();
    expect(el.querySelectorAll('.inbox-row').length).toBe(1);
  });

  it('assigns an asset without suggestion to a chosen project', () => {
    const { fixture, http, el } = setup();
    const row = el.querySelectorAll('.inbox-row')[1];
    const select = row.querySelector<HTMLSelectElement>('.assign-select')!;
    select.value = 'wuerth';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    row.querySelector<HTMLButtonElement>('.assign-btn')!.click();
    const req = http.expectOne('/api/assets/host/10/assign/');
    expect(req.request.body).toEqual({ project_slug: 'wuerth' });
  });

  it('shows monitoring toggle and Notion sync only for admins', () => {
    const admin = setup(true);
    expect(admin.el.querySelector('#notion-sync-btn')).toBeTruthy();
    expect(admin.el.querySelectorAll('.monitoring-toggle').length).toBe(2);
    TestBed.resetTestingModule();
    const member = setup(false);
    expect(member.el.querySelector('#notion-sync-btn')).toBeNull();
    expect(member.el.querySelectorAll('.monitoring-toggle').length).toBe(0);
  });

  it('toggles monitoring', () => {
    const { http, el } = setup();
    el.querySelector<HTMLInputElement>('.monitoring-toggle input')!.click();
    const req = http.expectOne('/api/triage-projects/wuerth/monitoring/');
    expect(req.request.body).toEqual({ monitored: false });
  });

  it('patches the deployment mode of a repository', () => {
    const { http, el } = setup();
    const select = el.querySelector<HTMLSelectElement>('.deployment-select')!;
    select.value = 'CONTAINER';
    select.dispatchEvent(new Event('change'));
    const req = http.expectOne('/api/repositories/3/');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ deployment_mode: 'CONTAINER' });
  });

  it('lists the containers assigned to a project', () => {
    const { el } = setup();
    const card = el.querySelector('[data-project="wuerth"]')!;
    const rows = Array.from(card.querySelectorAll('.asset-row')).map((r) => r.textContent ?? '');
    expect(rows.some((r) => r.includes('mdb.westcode.de: app') && r.includes('Container'))).toBe(true);
  });

  it('moves an assigned asset to another project', () => {
    const { fixture, http, el } = setup();
    const row = el.querySelector('[data-project="wuerth"] [data-asset="container:5"]')!;
    const select = row.querySelector<HTMLSelectElement>('.reassign-select')!;
    expect(Array.from(select.options).map((o) => o.value)).toEqual(['', 'alt']);
    select.value = 'alt';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    row.querySelector<HTMLButtonElement>('.move-btn')!.click();
    const req = http.expectOne('/api/assets/container/5/assign/');
    expect(req.request.body).toEqual({ project_slug: 'alt' });
    req.flush({});
    http.expectOne('/api/triage-projects/').flush(DATA);
  });

  it('removes an assigned asset from its project', () => {
    const { http, el } = setup();
    el.querySelector<HTMLButtonElement>('[data-project="wuerth"] [data-asset="host:4"] .unassign-btn')!.click();
    const req = http.expectOne('/api/assets/host/4/assign/');
    expect(req.request.body).toEqual({ project_slug: null });
  });

  it('shows no reassignment controls to non-admins', () => {
    const { el } = setup(false);
    expect(el.querySelector('.reassign-select')).toBeNull();
    expect(el.querySelector('.unassign-btn')).toBeNull();
  });

  it('shows the API error when an assignment fails', () => {
    const { fixture, http, el } = setup();
    el.querySelector<HTMLButtonElement>('[data-project="wuerth"] [data-asset="host:4"] .unassign-btn')!.click();
    http.expectOne('/api/assets/host/4/assign/').flush({ detail: 'Unbekanntes Projekt.' }, { status: 400, statusText: 'Bad Request' });
    fixture.detectChanges();
    expect(el.querySelector('.plan-check-note')?.textContent).toContain('Unbekanntes Projekt.');
  });

  it('marks projects that disappeared from Notion', () => {
    const { el } = setup();
    expect(el.querySelector('[data-project="alt"] .notion-missing')?.textContent).toContain('Nicht mehr in Notion');
  });
});
