import { HttpClient } from '@angular/common/http';
import { Injectable, InjectionToken, computed, inject, signal } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { firstValueFrom } from 'rxjs';
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

  logout(): Promise<void> {
    return firstValueFrom(this.http.post<void>('/api/auth/logout/', {})).then(() => {
      this.me.set(null);
      this.loading = null;
      this.redirect(LOGIN_URL);
    });
  }
}

export const authGuard: CanActivateFn = async () => (await inject(AuthService).load()) !== null;
