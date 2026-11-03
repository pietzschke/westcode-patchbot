import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';

export interface GitTargetDto {
  id?: number;
  repo_full_name: string;
  file_path: string;
  pr_number: number | null;
  pr_url?: string;
  ci_status: string;
  target_version?: string;
}

export interface HostTargetDto {
  id?: number;
  host_slug?: string;
  hostname: string;
  target_type?: string;
  working_dir: string;
  compose_service?: string;
  running_version: string;
  target_version: string;
  git_clean: boolean | null;
}

export interface VulnerabilityDto {
  id?: number;
  vulnerability_id: string;
  severity: string;
  status: string;
  fixed_version: string;
  title: string;
  package_name: string;
}

export interface ServiceGroupDto {
  id?: number;
  slug: string;
  display_name: string;
  logo_key: string;
  category: 'action_required' | 'ready' | string;
  current_version_summary: string;
  target_version: string;
  highest_cve_id?: string;
  highest_severity?: string;
  summary_line: string;
  git_targets: GitTargetDto[];
  host_targets: HostTargetDto[];
  vulnerabilities?: VulnerabilityDto[];
}

export interface RolloutStepDto {
  id: number;
  order: number;
  step_type: string;
  status: string;
  hostname?: string | null;
  host_slug?: string | null;
  repo_full_name?: string | null;
  pr_number?: number | null;
  pr_url?: string | null;
  working_dir?: string;
  compose_service?: string;
  target_version?: string;
  agent_job_id?: string | null;
  result_payload?: Record<string, unknown> | null;
}

export interface RolloutPlanDto {
  id: string;
  service_group: string;
  service_slug: string;
  service_display_name?: string;
  service_logo_key?: string;
  status: string;
  block_reason: string;
  created_at: string;
  steps: RolloutStepDto[];
}

export interface HostContainerDto {
  name: string;
  image_tag: string;
  oci_title?: string;
  oci_revision?: string;
  working_dir?: string;
  compose_service?: string;
  git_clean?: boolean | null;
  status?: string;
}

export interface HostPackageDto {
  name: string;
  installed_version: string;
  candidate_version: string;
  is_security_update: boolean;
}

export interface HostDto {
  id?: number;
  slug?: string;
  hostname: string;
  provider: string;
  stack_name?: string;
  stack?: string;
  declared_image?: string | null;
  os_distro?: string;
  distro?: string;
  os_version?: string;
  is_os_eol?: boolean;
  is_eol?: boolean;
  reboot_required?: boolean;
  last_seen_at?: string | null;
  has_agent_token?: boolean;
  pending_apt_count?: number;
  actionable_packages_count?: number;
  security_apt_count?: number;
  container_count?: number;
  containers_count?: number;
  containers?: HostContainerDto[];
  packages?: HostPackageDto[];
}

export interface HostTokenResponseDto {
  slug: string;
  hostname: string;
  token: string;
  install_command: string;
  host: HostDto;
}

export interface HostSshProbeResponseDto {
  detail: string;
  host: HostDto;
}

export interface LiveSyncSummaryDto {
  status: string;
  hosts_count: number;
  services_count: number;
  prs_count: number;
  vulns_count: number;
  synced_at: string;
}

@Injectable({ providedIn: 'root' })
export class PatchbotApi {
  private readonly http = inject(HttpClient);
  readonly refreshTick = signal<number>(0);

  listServices(): Observable<ServiceGroupDto[]> {
    return this.http.get<ServiceGroupDto[]>('/api/services/');
  }

  createServicePlan(slug: string): Observable<RolloutPlanDto> {
    return this.http.post<RolloutPlanDto>(`/api/services/${encodeURIComponent(slug)}/plan/`, {});
  }

  executePlan(planId: string): Observable<RolloutPlanDto> {
    return this.http.post<RolloutPlanDto>(`/api/plans/${encodeURIComponent(planId)}/execute/`, {});
  }

  listPlans(): Observable<RolloutPlanDto[]> {
    return this.http.get<RolloutPlanDto[]>('/api/plans/');
  }

  listHosts(): Observable<HostDto[]> {
    return this.http.get<HostDto[]>('/api/hosts/');
  }

  generateHostToken(slug: string): Observable<HostTokenResponseDto> {
    return this.http.post<HostTokenResponseDto>(`/api/hosts/${encodeURIComponent(slug)}/token/`, {});
  }

  probeHostSsh(slug: string): Observable<HostSshProbeResponseDto> {
    return this.http.post<HostSshProbeResponseDto>(
      `/api/hosts/${encodeURIComponent(slug)}/ssh-probe/`,
      {},
    );
  }

  triggerLiveSync(): Observable<LiveSyncSummaryDto> {
    return this.http.post<LiveSyncSummaryDto>('/api/sync/', {}).pipe(
      tap(() => {
        this.refreshTick.update((n) => n + 1);
      }),
    );
  }
}
