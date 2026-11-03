import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ServicesPage } from './services-page';
import { HostsPage } from './hosts-page';
import { SERVICE_LOGOS, getLogoSvg } from '../core/logos';

describe('ServicesPage', () => {
  it('renders service logos in two urgency groups and keeps a single primary action button in the plan panel', () => {
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
    expect(el.querySelector('#execute-plan-btn')?.textContent).toContain('Plan ausführen');
  });

  it('switches selected service on row click, keeps zero buttons in service rows, and executes rollout plan via API', () => {
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

    const execBtn = el.querySelector<HTMLButtonElement>('#execute-plan-btn')!;
    execBtn.click();

    const planReq = httpMock.expectOne('/api/services/postgres/plan/');
    expect(planReq.request.method).toBe('POST');
    planReq.flush({
      id: 'plan-123',
      service_group: 'postgres',
      service_slug: 'postgres',
      status: 'READY',
      block_reason: '',
      created_at: '2026-11-03T16:00:00Z',
      steps: [],
    });

    const execReq = httpMock.expectOne('/api/plans/plan-123/execute/');
    expect(execReq.request.method).toBe('POST');
    execReq.flush({
      id: 'plan-123',
      service_group: 'postgres',
      service_slug: 'postgres',
      status: 'RUNNING',
      block_reason: '',
      created_at: '2026-11-03T16:00:00Z',
      steps: [],
    });
    fixture.detectChanges();

    expect(el.querySelector('#p-status-block')?.textContent).toContain('RUNNING');
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
});
