import { ApplicationConfig } from '@angular/core';
import { provideHttpClient, withInterceptors, withXsrfConfiguration } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';
import { sessionExpiryInterceptor } from './core/auth';

/** Django CSRF: cookie `csrftoken` (set by /api/auth/me/), header `X-CSRFToken` on unsafe requests. */
export const XSRF_CONFIG = { cookieName: 'csrftoken', headerName: 'X-CSRFToken' };

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(withXsrfConfiguration(XSRF_CONFIG), withInterceptors([sessionExpiryInterceptor])),
  ],
};
