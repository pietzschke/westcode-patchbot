import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors, withXsrfConfiguration } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AuthService, LOGIN_REDIRECT, authGuard, sessionExpiryInterceptor } from './auth';
import { XSRF_CONFIG } from '../app.config';

const ME = {
  id: 1,
  name: 'Moritz Pietzschke',
  email: 'moritz.pietzschke@westcode.de',
  github_username: 'pietzschke',
  slack_user_id: 'U1',
  layers: ['application'],
  is_admin: true,
  is_default_infra_owner: false,
};

describe('AuthService', () => {
  it('redirects to Entra login when /api/auth/me/ is rejected', async () => {
    const redirect = vi.fn();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: LOGIN_REDIRECT, useValue: redirect }],
    });
    const auth = TestBed.inject(AuthService);
    const http = TestBed.inject(HttpTestingController);
    const loading = auth.load();
    http.expectOne('/api/auth/me/').flush({ detail: 'nope' }, { status: 403, statusText: 'Forbidden' });
    await loading;
    expect(redirect).toHaveBeenCalledWith('/api/auth/entra/login/');
    expect(auth.me()).toBeNull();
  });

  it('stores the logged-in member and loads only once', async () => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    const auth = TestBed.inject(AuthService);
    const http = TestBed.inject(HttpTestingController);
    const loading = auth.load();
    http.expectOne('/api/auth/me/').flush(ME);
    await loading;
    await auth.load();
    http.expectNone('/api/auth/me/');
    expect(auth.me()?.is_admin).toBe(true);
    expect(auth.isAdmin()).toBe(true);
  });

  it('guard allows navigation only for a loaded member', async () => {
    const redirect = vi.fn();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: LOGIN_REDIRECT, useValue: redirect }],
    });
    const http = TestBed.inject(HttpTestingController);
    const result = TestBed.runInInjectionContext(() => authGuard({} as never, {} as never)) as Promise<boolean>;
    http.expectOne('/api/auth/me/').flush(ME);
    expect(await result).toBe(true);
  });
});

describe('session expiry', () => {
  function setup() {
    const redirect = vi.fn();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([sessionExpiryInterceptor])), provideHttpClientTesting(),
        { provide: LOGIN_REDIRECT, useValue: redirect },
      ],
    });
    TestBed.inject(AuthService).me.set(ME);
    return { redirect, http: TestBed.inject(HttpTestingController), client: TestBed.inject(HttpClient) };
  }

  it('redirects to the login when an API call fails because the session expired', async () => {
    const { redirect, http, client } = setup();
    const errors: unknown[] = [];
    client.get('/api/dashboard/').subscribe({ error: (e) => errors.push(e) });
    http.expectOne('/api/dashboard/').flush({ detail: 'Anmeldedaten fehlen.' }, { status: 403, statusText: 'Forbidden' });
    expect(errors.length).toBe(1);
    http.expectOne('/api/auth/me/').flush({ detail: 'Anmeldedaten fehlen.' }, { status: 403, statusText: 'Forbidden' });
    await vi.waitFor(() => expect(redirect).toHaveBeenCalledWith('/api/auth/entra/login/'));
    expect(TestBed.inject(AuthService).me()).toBeNull();
  });

  it('stays on the page for a permission error while the session is still valid', async () => {
    const { redirect, http, client } = setup();
    client.post('/api/triage-projects/sync-notion/', {}).subscribe({ error: () => undefined });
    http.expectOne('/api/triage-projects/sync-notion/').flush({ detail: 'Keine Berechtigung.' }, { status: 403, statusText: 'Forbidden' });
    http.expectOne('/api/auth/me/').flush(ME);
    await Promise.resolve();
    expect(redirect).not.toHaveBeenCalled();
    expect(TestBed.inject(AuthService).me()).toEqual(ME);
  });

  it('ignores other errors', () => {
    const { http, client } = setup();
    client.get('/api/dashboard/').subscribe({ error: () => undefined });
    http.expectOne('/api/dashboard/').flush({}, { status: 500, statusText: 'Server Error' });
    http.expectNone('/api/auth/me/');
  });
});

describe('logout', () => {
  it('redirects to the login even if the session was already gone', async () => {
    const redirect = vi.fn();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: LOGIN_REDIRECT, useValue: redirect }],
    });
    const auth = TestBed.inject(AuthService);
    auth.me.set(ME);
    const done = auth.logout();
    TestBed.inject(HttpTestingController).expectOne('/api/auth/logout/').flush({}, { status: 403, statusText: 'Forbidden' });
    await done;
    expect(redirect).toHaveBeenCalledWith('/api/auth/entra/login/');
    expect(auth.me()).toBeNull();
  });
});

describe('CSRF', () => {
  it('sends X-CSRFToken from the csrftoken cookie on unsafe requests', () => {
    document.cookie = 'csrftoken=abc123';
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXsrfConfiguration(XSRF_CONFIG)), provideHttpClientTesting()],
    });
    TestBed.inject(HttpClient).post('/api/scans/run/', {}).subscribe();
    const req = TestBed.inject(HttpTestingController).expectOne('/api/scans/run/');
    expect(req.request.headers.get('X-CSRFToken')).toBe('abc123');
  });
});
