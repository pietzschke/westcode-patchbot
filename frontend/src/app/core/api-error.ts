import { HttpErrorResponse } from '@angular/common/http';

/** Flattens the `detail` of a DRF error response (string, list or field → messages map). */
export function apiErrorText(err: HttpErrorResponse, fallback: string): string {
  const detail: unknown = err.error?.detail;
  if (typeof detail === 'string' && detail) {
    return detail;
  }
  if (Array.isArray(detail) && detail.length) {
    return detail.join(' ');
  }
  if (detail && typeof detail === 'object') {
    const messages = Object.values(detail as Record<string, unknown>).flatMap((v) => (Array.isArray(v) ? v : [v]));
    if (messages.length) {
      return messages.join(' ');
    }
  }
  return fallback;
}
