import { HttpClient, HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Injectable, InjectionToken, computed, inject, signal } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { catchError, firstValueFrom, throwError } from 'rxjs';
import { MeDto } from './patchbot-api';

export const LOGIN_URL = '/api/auth/entra/login/';

/** Navigates the browser to the login URL; replaceable in tests. */
export const LOGIN_REDIRECT = new InjectionToken<(url: string) => void>('LOGIN_REDIRECT', {
  providedIn: 'root',
  factory: () => (url: string) => window.location.assign(url),
});

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly redirect = inject(LOGIN_REDIRECT);
  private loading: Promise<MeDto | null> | null = null;
  private verifying: Promise<void> | null = null;

  readonly me = signal<MeDto | null>(null);
  readonly isAdmin = computed(() => this.me()?.is_admin === true);

  load(): Promise<MeDto | null> {
    this.loading ??= firstValueFrom(this.http.get<MeDto>('/api/auth/me/')).then(
      (me) => {
        this.me.set(me);
        return me;
      },
      () => {
        this.me.set(null);
        this.loading = null;
        this.redirect(LOGIN_URL);
        return null;
      },
    );
    return this.loading;
  }

  /**
   * Called after an API call was rejected with 401/403. DRF answers an expired session and a missing
   * permission both with 403, so re-check /api/auth/me/ and only send the user to the login if the
   * session itself is gone.
   */
  verifySession(): Promise<void> {
    this.verifying ??= firstValueFrom(this.http.get<MeDto>('/api/auth/me/'))
      .then(
        (me) => this.me.set(me),
        (err: unknown) => {
          if (err instanceof HttpErrorResponse && (err.status === 401 || err.status === 403)) {
            this.sendToLogin();
          }
        },
      )
      .finally(() => (this.verifying = null));
    return this.verifying;
  }

  /** Ends the Django session (POST, CSRF header via withXsrfConfiguration) and returns to the login. */
  logout(): Promise<void> {
    return firstValueFrom(this.http.post<void>('/api/auth/logout/', {})).then(
      () => this.sendToLogin(),
      () => this.sendToLogin(),
    );
  }

  private sendToLogin(): void {
    this.me.set(null);
    this.loading = null;
    this.redirect(LOGIN_URL);
  }
}

/** Redirects to the login once the 12 h session has expired instead of leaving the UI half-broken. */
export const sessionExpiryInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  return next(req).pipe(
    catchError((err: unknown) => {
      if (
        err instanceof HttpErrorResponse &&
        (err.status === 401 || err.status === 403) &&
        !req.url.startsWith('/api/auth/')
      ) {
        void auth.verifySession();
      }
      return throwError(() => err);
    }),
  );
};

export const authGuard: CanActivateFn = async () => (await inject(AuthService).load()) !== null;
