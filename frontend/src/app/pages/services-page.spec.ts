import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ServicesPage } from './services-page';
import { HostsPage } from './hosts-page';
import { SERVICE_LOGOS, getLogoSvg } from '../core/logos';

describe('ServicesPage', () => {
  it('renders service logos in two urgency groups and keeps a single primary action button in the detail panel', () => {
    TestBed.configureTestingModule({
      imports: [ServicesPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const httpMock = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(ServicesPage);
    fixture.detectChanges();

    httpMock.expectOne('/api/services/').flush([
      {
        slug: 'plausible',
        display_name: 'Plausible Analytics',
        logo_key: 'plausible',
        category: 'action_required',
        current_version_summary: '2.1.0',
        target_version: '2.1.2',
        highest_cve_id: 'CVE-2026-3104',
        summary_line: 'Auth-Bypass im Klick-Tracking behoben',
        git_targets: [{ repo_full_name: 'westcoder/westcode-web', file_path: 'deploy/compose.yaml', pr_number: 142, ci_status: 'success' }],
        host_targets: [
          { hostname: 'c2.westcode.de', working_dir: '/opt/plausible', running_version: '2.1.0', target_version: '2.1.2', git_clean: true },
        ],
      },
    ]);
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('.service-row').length).toBe(1);
    expect(el.querySelector('.service-row .svc-logo svg')).toBeTruthy();
    expect(el.querySelectorAll('.btn-primary').length).toBe(1);
    expect(el.querySelector('#copy-runbook-btn')?.textContent).toContain('Runbook kopieren');
    expect(el.querySelector('#execute-plan-btn')).toBeNull();
  });

  it('switches selected service on row click, keeps zero buttons in service rows, and copies the runbook without any API call', () => {
    TestBed.configureTestingModule({
      imports: [ServicesPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const httpMock = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(ServicesPage);
    fixture.detectChanges();

    httpMock.expectOne('/api/services/').flush([
      {
        slug: 'plausible',
        display_name: 'Plausible Analytics',
        logo_key: 'plausible',
        category: 'action_required',
        current_version_summary: '2.1.0',
        target_version: '2.1.2',
        highest_cve_id: 'CVE-2026-3104',
        summary_line: 'Auth-Bypass im Klick-Tracking behoben',
        git_targets: [{ repo_full_name: 'westcoder/westcode-web', file_path: 'deploy/compose.yaml', pr_number: 142, ci_status: 'success' }],
        host_targets: [
          { hostname: 'c2.westcode.de', working_dir: '/opt/plausible', running_version: '2.1.0', target_version: '2.1.2', git_clean: true },
        ],
      },
      {
        slug: 'postgres',
        display_name: 'PostgreSQL (Alpine Container)',
        logo_key: 'postgres',
        category: 'ready',
        current_version_summary: '18.1',
        target_version: '18.2',
        summary_line: 'In Git bereits auf 18.2, auf 2 Hosts läuft noch 18.1',
        git_targets: [],
        host_targets: [
          { hostname: 'db1.westcode.de', working_dir: '/opt/postgres', running_version: '18.1', target_version: '18.2', git_clean: true },
        ],
      },
    ]);
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('.service-row').length).toBe(2);
    expect(el.querySelectorAll('.service-row button').length).toBe(0);

    const rows = el.querySelectorAll<HTMLElement>('.service-row');
    rows[1].click();
    fixture.detectChanges();

    expect(el.querySelector('#p-title')?.textContent).toContain('PostgreSQL (Alpine Container)');

    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });

    el.querySelector<HTMLButtonElement>('#copy-runbook-btn')!.click();

    expect(writeText).toHaveBeenCalledTimes(1);
    expect(writeText.mock.calls[0][0]).toContain('db1.westcode.de');
    httpMock.expectNone((req) => req.url.includes('/plan'));
    httpMock.verify();
  });

  it('provides inline SVG logos for all 9 core services and a fallback initial badge', () => {
    for (const key of ['plausible', 'django', 'postgres', 'coder', 'ubuntu', 'debian', 'traefik', 'valhalla', 'tileserver']) {
      expect(SERVICE_LOGOS[key]).toContain('<svg');
      expect(getLogoSvg(key, key)).toContain('<svg');
    }
    const fallback = getLogoSvg('unknown-service', 'Zammad Helpdesk');
    expect(fallback).toContain('<svg');
    expect(fallback).toContain('>Z</text>');
  });

  it('renders HostsPage with EOL badge and host counters', () => {
    TestBed.configureTestingModule({
      imports: [HostsPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const httpMock = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(HostsPage);
    fixture.detectChanges();

    httpMock.expectOne('/api/hosts/').flush([
      {
        hostname: 'linklama',
        provider: 'Hetzner',
        stack_name: 'linklama',
        os_distro: 'Ubuntu',
        os_version: '20.04',
        is_os_eol: true,
        container_count: 4,
        pending_apt_count: 12,
      },
    ]);
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('.host-row').length).toBe(1);
    expect(el.querySelector('.badge-eol')?.textContent).toContain('EOL');
  });

  it('opens the linked PR in a new tab without creating a rollout plan', () => {
    TestBed.configureTestingModule({
      imports: [ServicesPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const httpMock = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(ServicesPage);
    fixture.detectChanges();

    httpMock.expectOne('/api/services/').flush([
      {
        slug: 'plausible',
        display_name: 'Plausible Analytics',
        logo_key: 'plausible',
        category: 'action_required',
        current_version_summary: '2.1.0',
        target_version: '2.1.2',
        highest_cve_id: 'CVE-2026-3104',
        summary_line: 'Auth-Bypass im Klick-Tracking behoben',
        git_targets: [
          {
            repo_full_name: 'westcoder/westcode-web',
            file_path: 'deploy/compose.yaml',
            pr_number: 142,
            pr_url: 'https://github.com/westcoder/westcode-web/pull/142',
            ci_status: 'success',
          },
        ],
        host_targets: [],
      },
    ]);
    fixture.detectChanges();

    const openSpy = vi.spyOn(window, 'open').mockReturnValue(null);
    const el: HTMLElement = fixture.nativeElement;
    el.querySelector<HTMLButtonElement>('#open-pr-btn')!.click();

    expect(openSpy).toHaveBeenCalledWith('https://github.com/westcoder/westcode-web/pull/142', '_blank', 'noopener');
    httpMock.expectNone((req) => req.url.includes('/plan'));
    httpMock.verify();
    openSpy.mockRestore();
  });
});
