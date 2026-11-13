import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture } from '@angular/core/testing';
import { TeamPage } from './team-page';
import { AuthService } from '../core/auth';
import { MeDto, TeamMemberDto } from '../core/patchbot-api';

const TEAM: TeamMemberDto[] = [
  {
    id: 7, name: 'Moritz Pietzschke', email: 'moritz.pietzschke@westcode.de', github_username: 'mpietzschke',
    git_commit_emails: ['12345+mpietzschke@users.noreply.github.com'], slack_user_id: 'U07', layers: ['infrastructure', 'application'],
    is_default_infra_owner: true, is_admin: true, is_active: true,
  },
  {
    id: 9, name: 'Anna Beispiel', email: 'anna.beispiel@westcode.de', github_username: null,
    git_commit_emails: [], slack_user_id: null, layers: ['application'],
    is_default_infra_owner: false, is_admin: false, is_active: true,
  },
];

function me(isAdmin: boolean): MeDto {
  return { id: 7, name: 'Moritz', email: 'moritz.pietzschke@westcode.de', github_username: null, slack_user_id: 'U07',
    layers: [], is_admin: isAdmin, is_default_infra_owner: false };
}

function setup(isAdmin = true) {
  TestBed.configureTestingModule({
    imports: [TeamPage],
    providers: [provideHttpClient(), provideHttpClientTesting()],
  });
  TestBed.inject(AuthService).me.set(me(isAdmin));
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(TeamPage);
  fixture.detectChanges();
  http.expectOne('/api/team/').flush(TEAM);
  fixture.detectChanges();
  return { fixture, http, el: fixture.nativeElement as HTMLElement };
}

function type(fixture: ComponentFixture<TeamPage>, name: string, value: string): void {
  const input = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>(`.member-form input[name="${name}"]`)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
  fixture.detectChanges();
}

function check(fixture: ComponentFixture<TeamPage>, name: string): void {
  (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>(`.member-form input[name="${name}"]`)!.click();
  fixture.detectChanges();
}

function submit(fixture: ComponentFixture<TeamPage>): void {
  (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('.member-form .save-btn')!.click();
  fixture.detectChanges();
}

describe('TeamPage', () => {
  it('renders the team directory', () => {
    const { el } = setup();
    const rows = el.querySelectorAll<HTMLElement>('.team-row');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('moritz.pietzschke@westcode.de');
    expect(rows[0].textContent).toContain('mpietzschke');
    expect(rows[0].textContent).toContain('U07');
    expect(rows[0].textContent).toContain('Infrastruktur');
    expect(rows[0].textContent).toContain('Admin');
    expect(rows[0].textContent).toContain('Infra-Owner');
    expect(rows[1].textContent).toContain('Anwendung');
  });

  it('shows a read-only table to non-admins', () => {
    const { el } = setup(false);
    expect(el.querySelectorAll('.team-row').length).toBe(2);
    expect(el.querySelector('#add-member-btn')).toBeNull();
    expect(el.querySelector('.edit-btn')).toBeNull();
    expect(el.querySelector('.test-dm-btn')).toBeNull();
    expect(el.querySelector('.member-form')).toBeNull();
  });

  it('rejects non-westcode e-mail addresses before sending a request', () => {
    const { fixture, http, el } = setup();
    el.querySelector<HTMLButtonElement>('#add-member-btn')!.click();
    fixture.detectChanges();
    type(fixture, 'name', 'Extern');
    type(fixture, 'email', 'extern@gmail.com');
    submit(fixture);
    http.expectNone('/api/team/');
    expect(el.querySelector('.member-form .action-error')?.textContent).toContain('@westcode.de');
  });

  it('adds a member with layers and flags', () => {
    const { fixture, http, el } = setup();
    el.querySelector<HTMLButtonElement>('#add-member-btn')!.click();
    fixture.detectChanges();
    type(fixture, 'name', 'Neu Kollege');
    type(fixture, 'email', 'Neu.Kollege@westcode.de');
    type(fixture, 'github_username', 'neukollege');
    check(fixture, 'layer-application');
    check(fixture, 'is_admin');
    submit(fixture);
    const req = http.expectOne((r) => r.method === 'POST' && r.url === '/api/team/');
    expect(req.request.body).toEqual({
      name: 'Neu Kollege', email: 'neu.kollege@westcode.de', github_username: 'neukollege', slack_user_id: null,
      git_commit_emails: [], layers: ['application'], is_admin: true, is_default_infra_owner: false, is_active: true,
    });
    req.flush({ ...TEAM[1], id: 11, name: 'Neu Kollege' }, { status: 201, statusText: 'Created' });
    http.expectOne((r) => r.method === 'GET' && r.url === '/api/team/').flush([...TEAM, { ...TEAM[1], id: 11, name: 'Neu Kollege' }]);
    fixture.detectChanges();
    expect(el.querySelectorAll('.team-row').length).toBe(3);
    expect(el.querySelector('.member-form')).toBeNull();
  });

  it('edits a member and toggles layers, admin and infra owner', () => {
    const { fixture, http, el } = setup();
    el.querySelectorAll<HTMLElement>('.team-row')[1].querySelector<HTMLButtonElement>('.edit-btn')!.click();
    fixture.detectChanges();
    expect(el.querySelector<HTMLInputElement>('.member-form input[name="email"]')!.value).toBe('anna.beispiel@westcode.de');
    check(fixture, 'layer-infrastructure');
    check(fixture, 'is_admin');
    check(fixture, 'is_default_infra_owner');
    type(fixture, 'slack_user_id', 'U09');
    submit(fixture);
    const req = http.expectOne('/api/team/9/');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({
      name: 'Anna Beispiel', email: 'anna.beispiel@westcode.de', github_username: null, slack_user_id: 'U09',
      git_commit_emails: [], layers: ['infrastructure', 'application'], is_admin: true, is_default_infra_owner: true, is_active: true,
    });
  });

  it('shows the git commit e-mail aliases in the directory', () => {
    const { el } = setup();
    expect(el.querySelectorAll<HTMLElement>('.team-row')[0].textContent).toContain('12345+mpietzschke@users.noreply.github.com');
  });

  it('edits the git commit e-mail aliases', () => {
    const { fixture, http, el } = setup();
    el.querySelectorAll<HTMLElement>('.team-row')[0].querySelector<HTMLButtonElement>('.edit-btn')!.click();
    fixture.detectChanges();
    const input = el.querySelector<HTMLInputElement>('.member-form input[name="git_commit_emails"]')!;
    expect(input.value).toBe('12345+mpietzschke@users.noreply.github.com');
    type(fixture, 'git_commit_emails', '12345+mpietzschke@users.noreply.github.com,  Moritz@Privat.de; m@old.de');
    submit(fixture);
    const req = http.expectOne('/api/team/7/');
    expect(req.request.body.git_commit_emails).toEqual([
      '12345+mpietzschke@users.noreply.github.com', 'moritz@privat.de', 'm@old.de',
    ]);
  });

  it('rejects git commit aliases that are not e-mail addresses', () => {
    const { fixture, http, el } = setup();
    el.querySelectorAll<HTMLElement>('.team-row')[1].querySelector<HTMLButtonElement>('.edit-btn')!.click();
    fixture.detectChanges();
    type(fixture, 'git_commit_emails', 'anna, anna@privat.de');
    submit(fixture);
    http.expectNone('/api/team/9/');
    expect(el.querySelector('.member-form .action-error')?.textContent).toContain('anna');
  });

  it('shows API validation errors', () => {
    const { fixture, http, el } = setup();
    el.querySelectorAll<HTMLElement>('.team-row')[1].querySelector<HTMLButtonElement>('.edit-btn')!.click();
    fixture.detectChanges();
    check(fixture, 'is_active');
    submit(fixture);
    http.expectOne('/api/team/9/').flush(
      { detail: { is_default_infra_owner: ['Genau ein aktives Teammitglied muss Infra-Owner sein.'] } },
      { status: 400, statusText: 'Bad Request' },
    );
    fixture.detectChanges();
    expect(el.querySelector('.member-form .action-error')?.textContent).toContain(
      'Genau ein aktives Teammitglied muss Infra-Owner sein.',
    );
    expect(el.querySelector('.member-form')).toBeTruthy();
  });

  it('triggers a Slack test DM', () => {
    const { fixture, http, el } = setup();
    const btn = el.querySelectorAll<HTMLElement>('.team-row')[0].querySelector<HTMLButtonElement>('.test-dm-btn')!;
    expect(btn.textContent).toContain('Test-DM senden');
    btn.click();
    const req = http.expectOne('/api/team/7/test-dm/');
    expect(req.request.method).toBe('POST');
    req.flush(null, { status: 202, statusText: 'Accepted' });
    fixture.detectChanges();
    expect(el.querySelector('.plan-check-note')?.textContent).toContain('Test-DM an Moritz Pietzschke');
  });
});
