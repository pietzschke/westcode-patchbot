import { FindingDto } from './patchbot-api';

/** "Projekt · CVE-…" — or the host / image when a finding has no CVE (e.g. OS end-of-life). */
export function findingSubline(f: Pick<FindingDto, 'project' | 'vulnerability_ids' | 'target_ref'>): string {
  const ids = f.vulnerability_ids.join(', ');
  const target = (f.target_ref ?? '').replace(/^(host|image|repo):/, '');
  return [f.project?.name, ids || target].filter(Boolean).join(' · ');
}
