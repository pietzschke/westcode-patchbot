import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withXsrfConfiguration } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AuthService, LOGIN_REDIRECT, authGuard } from './auth';
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
