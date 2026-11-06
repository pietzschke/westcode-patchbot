import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface HostContainerDto {
  name: string;
  image_tag: string;
  repo_digests?: string[];
  oci_title?: string;
  oci_revision?: string;
  oci_source?: string;
  /** Build time of the image — a display hint only, never a verification proof. */
  image_created_at?: string | null;
  working_dir?: string;
  compose_service?: string;
  git_head_sha?: string;
  git_clean?: boolean | null;
  status?: string;
}

/** A pending apt upgrade (installed-only packages are not listed). */
export interface HostPackageDto {
  name: string;
  installed_version: string;
  candidate_version: string;
  is_security_update: boolean;
  source_pocket?: string;
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
  os_eol_date?: string | null;
  is_os_eol?: boolean;
  is_eol?: boolean;
  kernel_version?: string;
  reboot_required?: boolean;
  agent_version?: string;
  apt_lists_updated_at?: string | null;
  last_seen_at?: string | null;
  has_agent_token?: boolean;
  project?: { slug: string; name: string } | null;
  installed_package_count?: number;
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


// ---------------------------------------------------------------------------
// v2 control plane
// ---------------------------------------------------------------------------
export type AmpelColor = 'GREY' | 'RED' | 'YELLOW' | 'GREEN';

export interface AmpelCauseDto {
  code: string;
  text: string;
}

export interface AmpelDto {
  color: AmpelColor;
  label_de: string;
  findings_color: AmpelColor;
  causes: AmpelCauseDto[];
  counts: Record<string, number>;
  computed_at: string;
}

export interface RefDto {
  id: number;
  name: string;
}

export interface ProjectRefV2Dto {
  slug: string;
  name: string;
}

export interface PrInfoDto {
  number: number;
  url: string;
  draft: boolean;
  source: string;
  ci_status: string;
}

export interface FindingDto {
  id: number;
  title: string;
  project: ProjectRefV2Dto;
  layer: string;
  target_ref: string;
  package_name: string;
  current_version: string;
  target_version: string;
  vulnerability_ids: string[];
  highest_severity: string;
  kev_listed: boolean;
  state: string;
  complexity: string;
  triage_status: string;
  assignee: RefDto | null;
  deadline_at: string | null;
  overdue: boolean;
  pr: PrInfoDto | null;
}

export interface VerificationRowDto {
  host: string;
  container: string;
  fresh: boolean;
  proof: 'REVISION' | 'CHECKOUT' | 'SCAN' | null;
  oci_revision?: string;
  git_head_sha?: string;
  image_created_at?: string | null;
  pr_merged_at?: string | null;
}

export interface FindingEventDto {
  at: string;
  actor: RefDto | null;
  source: string;
  from_state: string;
  to_state: string;
  note: string;
}

export interface FindingDetailDto extends FindingDto {
  reachability: string;
  confidence: number | null;
  summary_de: string;
  breaking_changes_de: string;
  affected_files: string[];
  assigned_reason_de: string;
  discovered_at: string | null;
  acknowledged_at: string | null;
  pr_merged_at: string | null;
  verified_live_at: string | null;
  extended_in_stage: string;
  dismissal: { mode: string; reason: string; by: RefDto | null; snoozed_until: string | null } | null;
  manual_runbook: string;
  verification: VerificationRowDto[];
  verification_checked_at: string | null;
  needs_deployment_decision: boolean;
  repository_id: number | null;
  events: FindingEventDto[];
}

export interface MaintenanceUpdateDto {
  id: number;
  project: ProjectRefV2Dto;
  repository: string;
  package_name: string;
  current_version: string;
  target_version: string;
  update_type: string;
  pr_number: number;
  pr_url: string;
  ci_status: string;
  summary_de: string;
}

export interface DashboardDto {
  ampel: AmpelDto;
  buckets: { simple: FindingDto[]; complex: FindingDto[]; waiting_live: FindingDto[] };
  filtered: FindingDto[];
  maintenance: MaintenanceUpdateDto[];
  me_id: number;
}

export type AssetType = 'repository' | 'host' | 'container';

export interface AssetDto {
  id: number;
  type: AssetType;
  name: string;
  suggested_project: ProjectRefV2Dto | null;
  deployment_mode?: string;
  is_archived?: boolean;
  has_bot_updates?: boolean;
  image?: string;
}

export interface TriageProjectDto {
  slug: string;
  name: string;
  customer_name: string;
  is_internal: boolean;
  notion_status: string;
  notion_missing: boolean;
  is_monitored: boolean;
  owner: RefDto | null;
  last_notion_synced_at: string | null;
  repositories: AssetDto[];
  hosts: AssetDto[];
  containers: AssetDto[];
  open_findings: number;
}

export interface TriageProjectsDto {
  projects: TriageProjectDto[];
  unassigned_assets: { repositories: AssetDto[]; hosts: AssetDto[]; containers: AssetDto[] };
}

export interface TeamMemberDto {
  id: number;
  name: string;
  email: string;
  github_username: string | null;
  git_commit_emails: string[];
  slack_user_id: string | null;
  layers: string[];
  is_default_infra_owner: boolean;
  is_admin: boolean;
  is_active: boolean;
}

export interface MeDto {
  id: number;
  name: string;
  email: string;
  github_username: string | null;
  slack_user_id: string | null;
  layers: string[];
  is_admin: boolean;
  is_default_infra_owner: boolean;
}

export interface ScanStatusDto {
  running: boolean;
  job_id: number | null;
  scan_run: {
    id: number;
    status: 'RUNNING' | 'OK' | 'PARTIAL' | 'FAILED';
    started_at: string;
    finished_at: string | null;
    targets_done: number;
  } | null;
}

export interface DismissPayload {
  mode: 'DISMISSED' | 'SNOOZED';
  reason: string;
  snooze_days?: 14 | 30;
}

@Injectable({ providedIn: 'root' })
export class PatchbotApi {
  private readonly http = inject(HttpClient);

  listHosts(): Observable<HostDto[]> {
    return this.http.get<HostDto[]>('/api/hosts/');
  }

  generateHostToken(slug: string): Observable<HostTokenResponseDto> {
    return this.http.post<HostTokenResponseDto>(`/api/hosts/${encodeURIComponent(slug)}/token/`, {});
  }

  // --- v2 control plane ---------------------------------------------------
  getDashboard(): Observable<DashboardDto> {
    return this.http.get<DashboardDto>('/api/dashboard/');
  }

  getFinding(id: number): Observable<FindingDetailDto> {
    return this.http.get<FindingDetailDto>(`/api/findings/${id}/`);
  }

  acknowledgeFinding(id: number): Observable<FindingDetailDto> {
    return this.http.post<FindingDetailDto>(`/api/findings/${id}/acknowledge/`, {});
  }

  dismissFinding(id: number, payload: DismissPayload): Observable<FindingDetailDto> {
    return this.http.post<FindingDetailDto>(`/api/findings/${id}/dismiss/`, payload);
  }

  reopenFinding(id: number, note = ''): Observable<FindingDetailDto> {
    return this.http.post<FindingDetailDto>(`/api/findings/${id}/reopen/`, { note });
  }

  extendFinding(id: number, reason: string): Observable<FindingDetailDto> {
    return this.http.post<FindingDetailDto>(`/api/findings/${id}/extend/`, { reason });
  }

  requestMaintenanceAnalysis(id: number): Observable<void> {
    return this.http.post<void>(`/api/maintenance/${id}/request-analysis/`, {});
  }

  listTriageProjects(): Observable<TriageProjectsDto> {
    return this.http.get<TriageProjectsDto>('/api/triage-projects/');
  }

  syncNotion(): Observable<void> {
    return this.http.post<void>('/api/triage-projects/sync-notion/', {});
  }

  setMonitoring(slug: string, monitored: boolean): Observable<TriageProjectDto> {
    return this.http.post<TriageProjectDto>(`/api/triage-projects/${encodeURIComponent(slug)}/monitoring/`, { monitored });
  }

  confirmSuggestion(type: AssetType, id: number): Observable<unknown> {
    return this.http.post(`/api/assets/${type}/${id}/confirm-suggestion/`, {});
  }

  assignAsset(type: AssetType, id: number, projectSlug: string | null): Observable<unknown> {
    return this.http.post(`/api/assets/${type}/${id}/assign/`, { project_slug: projectSlug });
  }

  setDeploymentMode(repositoryId: number, mode: string): Observable<AssetDto> {
    return this.http.patch<AssetDto>(`/api/repositories/${repositoryId}/`, { deployment_mode: mode });
  }

  listTeam(): Observable<TeamMemberDto[]> {
    return this.http.get<TeamMemberDto[]>('/api/team/');
  }

  createTeamMember(payload: Partial<TeamMemberDto>): Observable<TeamMemberDto> {
    return this.http.post<TeamMemberDto>('/api/team/', payload);
  }

  updateTeamMember(id: number, payload: Partial<TeamMemberDto>): Observable<TeamMemberDto> {
    return this.http.patch<TeamMemberDto>(`/api/team/${id}/`, payload);
  }

  sendTestDm(id: number): Observable<void> {
    return this.http.post<void>(`/api/team/${id}/test-dm/`, {});
  }

  getScanStatus(): Observable<ScanStatusDto> {
    return this.http.get<ScanStatusDto>('/api/scans/run/');
  }

  runScan(): Observable<{ job_id: number }> {
    return this.http.post<{ job_id: number }>('/api/scans/run/', {});
  }
}
