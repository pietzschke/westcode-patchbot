import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { HostsPage } from './hosts-page';
import { AuthService } from '../core/auth';
import { HostDto, MeDto } from '../core/patchbot-api';

const MINUTE = 60_000;

function ago(minutes: number): string {
  return new Date(Date.now() - minutes * MINUTE).toISOString();
}

function hosts(): HostDto[] {
  return [
    {
      slug: 'mdb', hostname: 'mdb.westcode.de', provider: 'hetzner', stack_name: 'hetzner-mdb',
      os_distro: 'Ubuntu', os_version: '22.04', os_eol_date: '2027-04-30', is_os_eol: false,
      kernel_version: '5.15.0-113-generic', reboot_required: true, agent_version: '2.0.0',
      last_seen_at: ago(5), apt_lists_updated_at: ago(30 * 60), has_agent_token: true,
      project: { slug: 'wuerth', name: 'Würth' }, installed_package_count: 612,
      pending_apt_count: 2, security_apt_count: 1, container_count: 1,
      containers: [{
        name: 'mdb-web', image_tag: 'ghcr.io/westcoder/mdb:main',
        repo_digests: ['ghcr.io/westcoder/mdb@sha256:deadbeefcafe0123456789'],
        oci_revision: 'abc1234', oci_source: 'https://github.com/westcoder/materialdatenbank',
        image_created_at: '2026-11-01T12:30:00Z', working_dir: '/opt/mdb', git_head_sha: 'def4567890abcdef',
        git_clean: false, status: 'running',
      }],
      packages: [
        { name: 'openssl', installed_version: '3.0.2-0ubuntu1.10', candidate_version: '3.0.2-0ubuntu1.15',
          is_security_update: true, source_pocket: 'jammy-security' },
        { name: 'tzdata', installed_version: '2024a', candidate_version: '2024b', is_security_update: false,
          source_pocket: 'jammy-updates' },
      ],
    },
    {
      slug: 'web', hostname: 'web.westcode.de', provider: 'hetzner', stack_name: 'hetzner-web',
      os_distro: 'Ubuntu', os_version: '24.04', last_seen_at: ago(90), apt_lists_updated_at: ago(120),
      containers: [], packages: [],
    },
    {
      slug: 'fresh', hostname: 'fresh.westcode.de', provider: 'aws', stack_name: 'aws-fresh',
      last_seen_at: null, apt_lists_updated_at: null, containers: [], packages: [],
    },
  ];
}

function me(isAdmin: boolean): MeDto {
  return { id: 7, name: 'Moritz', email: 'm@westcode.de', github_username: null, slack_user_id: 'U1', layers: [],
    is_admin: isAdmin, is_default_infra_owner: false };
}

function setup(isAdmin = true) {
  TestBed.configureTestingModule({
    imports: [HostsPage],
    providers: [provideHttpClient(), provideHttpClientTesting()],
  });
  TestBed.inject(AuthService).me.set(me(isAdmin));
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(HostsPage);
  fixture.detectChanges();
  http.expectOne('/api/hosts/').flush(hosts());
  fixture.detectChanges();
  return { fixture, http, el: fixture.nativeElement as HTMLElement };
}

function row(el: HTMLElement, slug: string): HTMLElement {
  return el.querySelector<HTMLElement>(`.host-row[data-host="${slug}"]`)!;
}

describe('HostsPage (v2)', () => {
  it('shows the dynamic host count in the title', () => {
    const { el } = setup();
    expect(el.querySelector('.page-title')?.textContent).toContain('Live-Hosts (3)');
    expect(el.querySelectorAll('.host-row').length).toBe(3);
  });

  it('flags stale telemetry after 60 minutes or when the agent never reported', () => {
    const { el } = setup();
    expect(row(el, 'mdb').querySelector('.badge-telemetry-stale')).toBeNull();
    expect(row(el, 'web').querySelector('.badge-telemetry-stale')?.textContent).toContain('Telemetrie veraltet');
    expect(row(el, 'fresh').querySelector('.badge-telemetry-stale')?.textContent).toContain('Telemetrie veraltet');
  });

  it('flags apt lists older than 26 hours', () => {
    const { el } = setup();
    expect(row(el, 'mdb').querySelector('.badge-apt-stale')?.textContent).toContain('apt-Listen veraltet');
    expect(row(el, 'web').querySelector('.badge-apt-stale')).toBeNull();
  });

  it('renders container provenance: digest, OCI revision, image build date as hint and git state', () => {
    const { el } = setup();
    const container = el.querySelector<HTMLElement>('.container-row')!;
    const text = container.textContent ?? '';
    expect(text).toContain('mdb-web');
    expect(text).toContain('sha256:deadbeefcafe');
    expect(text).toContain('abc1234');
    expect(container.querySelector('.image-built')?.textContent).toContain('Image gebaut am 01.11.2026');
    expect(container.querySelector('.image-built')?.textContent).toContain('Hinweis');
    expect(container.querySelector('.git-state')?.textContent).toContain('def4567');
    expect(container.querySelector('.git-state')?.textContent).toContain('dirty');
  });

  it('lists pending apt upgrades with security flag and pocket, plus kernel and reboot state', () => {
    const { el } = setup();
    const pkgs = el.querySelectorAll<HTMLElement>('.package-row');
    expect(pkgs.length).toBe(2);
    expect(pkgs[0].textContent).toContain('openssl');
    expect(pkgs[0].querySelector('.sev-badge')?.textContent).toContain('Security');
    expect(pkgs[0].textContent).toContain('jammy-security');
    expect(pkgs[1].querySelector('.sev-badge')).toBeNull();
    const facts = el.querySelector('.host-facts')?.textContent ?? '';
    expect(facts).toContain('5.15.0-113-generic');
    expect(facts).toContain('Neustart erforderlich');
    expect(facts).toContain('612');
  });

  it('switches the detail panel when another host is selected', () => {
    const { fixture, el } = setup();
    row(el, 'web').click();
    fixture.detectChanges();
    expect(el.querySelector('.plan-title')?.textContent).toContain('web.westcode.de');
    expect(el.querySelectorAll('.container-row').length).toBe(0);
  });

  it('offers the agent token generator to admins and shows the install command once', () => {
    const { fixture, http, el } = setup(true);
    el.querySelector<HTMLButtonElement>('#agent-token-btn')!.click();
    const req = http.expectOne('/api/hosts/mdb/token/');
    expect(req.request.method).toBe('POST');
    const cmd = 'sudo PATCHBOT_URL=https://patch.westcode.de PATCHBOT_TOKEN=tok PATCHBOT_HOSTNAME=mdb.westcode.de ./deploy/install-agent.sh';
    req.flush({ slug: 'mdb', hostname: 'mdb.westcode.de', token: 'tok', install_command: cmd, host: hosts()[0] });
    fixture.detectChanges();
    expect(el.querySelector('.install-command')?.textContent).toContain(cmd);
    row(el, 'web').click();
    fixture.detectChanges();
    expect(el.querySelector('.install-command')).toBeNull();
  });

  it('hides the agent token generator from non-admins', () => {
    const { el } = setup(false);
    expect(el.querySelector('#agent-token-btn')).toBeNull();
  });
});
