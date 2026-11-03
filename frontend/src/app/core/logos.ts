export const SERVICE_LOGOS: Record<string, string> = {
  plausible: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect x="4" y="13" width="4" height="7" rx="1.5" fill="#5a61fb"/>
    <rect x="10" y="8" width="4" height="12" rx="1.5" fill="#5a61fb"/>
    <rect x="16" y="4" width="4" height="16" rx="1.5" fill="#1d26db"/>
  </svg>`,
  django: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect width="24" height="24" rx="5" fill="#092E20"/>
    <text x="12" y="16.5" text-anchor="middle" fill="#ffffff" font-weight="700" font-size="11" font-family="system-ui, sans-serif">dj</text>
  </svg>`,
  postgres: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect width="24" height="24" rx="5" fill="#336791"/>
    <text x="12" y="16" text-anchor="middle" fill="#ffffff" font-weight="700" font-size="10.5" font-family="system-ui, sans-serif">PG</text>
  </svg>`,
  coder: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect width="24" height="24" rx="5" fill="#0f0f10"/>
    <path d="M8 9L5 12L8 15M16 9L19 12L16 15M13 7L11 17" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`,
  ubuntu: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <circle cx="12" cy="12" r="10" fill="#E95420"/>
    <circle cx="12" cy="12" r="4.2" stroke="#ffffff" stroke-width="2"/>
    <circle cx="12" cy="4.5" r="1.6" fill="#ffffff"/>
    <circle cx="5.8" cy="15.8" r="1.6" fill="#ffffff"/>
    <circle cx="18.2" cy="15.8" r="1.6" fill="#ffffff"/>
  </svg>`,
  debian: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <circle cx="12" cy="12" r="10" fill="#A80030"/>
    <path d="M13.5 7.5C10.5 7 8 9.2 8.2 12.2C8.4 15 11 16.8 13.8 16.2C15.5 15.8 16.5 14.2 16.2 12.5C15.9 10.8 14.2 9.8 12.6 10.3C11.2 10.8 10.8 12.4 11.8 13.4" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round"/>
  </svg>`,
  traefik: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect width="24" height="24" rx="5" fill="#24A1C1"/>
    <path d="M7 16L12 7L17 16H7Z" stroke="#ffffff" stroke-width="2" stroke-linejoin="round"/>
  </svg>`,
  valhalla: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect width="24" height="24" rx="5" fill="#1d6b40"/>
    <path d="M6 7L12 17L18 7" stroke="#ffffff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`,
  tileserver: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect width="24" height="24" rx="5" fill="#313235"/>
    <rect x="5" y="5" width="6" height="6" rx="1" fill="#ffffff"/>
    <rect x="13" y="5" width="6" height="6" rx="1" fill="#5a61fb"/>
    <rect x="5" y="13" width="6" height="6" rx="1" fill="#5a61fb"/>
    <rect x="13" y="13" width="6" height="6" rx="1" fill="#ffffff"/>
  </svg>`,
};

export function getLogoSvg(key: string, name: string): string {
  const normalizedKey = (key || '').trim().toLowerCase();
  if (normalizedKey && SERVICE_LOGOS[normalizedKey]) {
    return SERVICE_LOGOS[normalizedKey];
  }
  const initial = ((name || key || '?').trim().charAt(0) || '?')
    .toUpperCase()
    .replace(/[^A-Z0-9ÄÖÜ]/g, '?');
  return `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect width="24" height="24" rx="5" fill="#515256"/>
    <text x="12" y="16" text-anchor="middle" fill="#ffffff" font-weight="700" font-size="11" font-family="system-ui, sans-serif">${initial}</text>
  </svg>`;
}
