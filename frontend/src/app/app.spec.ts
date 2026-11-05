import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { App, SCAN_POLL_MS } from './app';
import { AuthService, LOGIN_REDIRECT } from './core/auth';

const IDLE = { running: false, job_id: null, scan_run: null };

function setup(initialStatus: object = IDLE) {
  const redirect = vi.fn();
  TestBed.configureTestingModule({
    imports: [App],
    providers: [
      provideRouter([]), provideHttpClient(), provideHttpClientTesting(),
      { provide: LOGIN_REDIRECT, useValue: redirect },
    ],
  });
  TestBed.inject(AuthService).me.set({
    id: 7, name: 'Moritz', email: 'm@westcode.de', github_username: null, slack_user_id: null, layers: [],
    is_admin: false, is_default_infra_owner: false,
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(App);
  fixture.detectChanges();
  http.expectOne('/api/scans/run/').flush(initialStatus);
  fixture.detectChanges();
  const el = fixture.nativeElement as HTMLElement;
  const button = () => el.querySelector<HTMLButtonElement>('#run-scan-btn')!;
  const status = () => el.querySelector('.scan-status')?.textContent ?? '';
  return { fixture, http, el, button, status, redirect };
}

describe('App header', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('keeps the scan button disabled until the scan run has finished', () => {
    const { fixture, http, button, status } = setup();
    expect(button().disabled).toBe(false);
    button().click();
    fixture.detectChanges();
    const start = http.expectOne((r) => r.method === 'POST' && r.url === '/api/scans/run/');
    start.flush({ job_id: 11 }, { status: 202, statusText: 'Accepted' });
    fixture.detectChanges();
    expect(button().disabled).toBe(true);

    vi.advanceTimersByTime(SCAN_POLL_MS);
    http.expectOne((r) => r.method === 'GET' && r.url === '/api/scans/run/').flush({
      running: true, job_id: 11,
      scan_run: { id: 3, status: 'RUNNING', started_at: '2026-11-05T08:00:00Z', finished_at: null, targets_done: 4 },
    });
    fixture.detectChanges();
    expect(button().disabled).toBe(true);
    expect(status()).toContain('4 Ziele');

    vi.advanceTimersByTime(SCAN_POLL_MS);
    http.expectOne((r) => r.method === 'GET' && r.url === '/api/scans/run/').flush({
      running: false, job_id: null,
      scan_run: { id: 3, status: 'OK', started_at: '2026-11-05T08:00:00Z', finished_at: '2026-11-05T08:10:00Z',
        targets_done: 9 },
    });
    fixture.detectChanges();
    expect(button().disabled).toBe(false);
    expect(status()).toContain('abgeschlossen');
    vi.advanceTimersByTime(SCAN_POLL_MS * 3);
    http.expectNone('/api/scans/run/');
  });

  it('starts disabled and polls when a scan is already running on load', () => {
    const { fixture, http, button } = setup({ running: true, job_id: 5, scan_run: null });
    expect(button().disabled).toBe(true);
    vi.advanceTimersByTime(SCAN_POLL_MS);
    http.expectOne('/api/scans/run/').flush(IDLE);
    fixture.detectChanges();
    expect(button().disabled).toBe(false);
  });

  it('treats a 409 as "scan already running" and waits for it', () => {
    const { fixture, http, button, status } = setup();
    button().click();
    http.expectOne((r) => r.method === 'POST').flush({ detail: 'Ein Scan läuft bereits.' }, { status: 409, statusText: 'Conflict' });
    fixture.detectChanges();
    expect(button().disabled).toBe(true);
    expect(status()).toContain('läuft bereits');
    vi.advanceTimersByTime(SCAN_POLL_MS);
    http.expectOne('/api/scans/run/').flush(IDLE);
    fixture.detectChanges();
    expect(button().disabled).toBe(false);
  });

  it('logs out via POST and redirects to the login', async () => {
    const { el, http, redirect } = setup();
    el.querySelector<HTMLButtonElement>('#logout-btn')!.click();
    const req = http.expectOne('/api/auth/logout/');
    expect(req.request.method).toBe('POST');
    req.flush(null, { status: 204, statusText: 'No Content' });
    await vi.waitFor(() => expect(redirect).toHaveBeenCalledWith('/api/auth/entra/login/'));
  });
});
