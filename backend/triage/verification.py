"""Live verification (spec v2.1 §6.4): a finding is only closed once the fix demonstrably runs.

Application findings (after merge) need ≥ 1 linked running container, fresh
telemetry from every linked host (reported after the merge) and, per container,
one proof: (a) the image revision contains the merge commit, (b) the host
checkout contains it, or (c) a scan of the running digest no longer shows the
CVE. ``image_created_at`` is only a hint, never a proof.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable

from django.utils import timezone

from fleet.models import HostContainer
from triage.findings import log_event
from triage.models import Finding
from triage.versions import compare_versions

APT_LISTS_MAX_AGE = timedelta(hours=26)
EOL_WARNING_DAYS = 90
CONTAINS_MERGE = {"identical", "ahead"}

ImageScanLookup = Callable[[str], dict | None]


def _digest(container: HostContainer) -> str:
    return next((d for d in container.repo_digests or [] if "@sha256:" in d), "")


def _scan_is_clean(scan: dict | None, finding: Finding) -> bool:
    if not scan or scan.get("status") != "OK":
        return False
    ids = set(finding.vulnerability_ids)
    package = finding.package_name.lower()
    return not any(
        v.get("id") in ids or str(v.get("package", "")).lower() == package for v in scan.get("vulnerabilities") or []
    )


def _container_proof(finding: Finding, container: HostContainer, github, lookup: ImageScanLookup) -> str | None:
    repo = finding.repository
    merge = finding.merge_commit_sha
    if merge and container.oci_revision and github.compare(repo.full_name, merge, container.oci_revision) in CONTAINS_MERGE:
        return "REVISION"
    if (
        merge
        and repo.deployment_mode == "HOST_CHECKOUT"
        and container.git_head_sha
        and github.compare(repo.full_name, merge, container.git_head_sha) in CONTAINS_MERGE
    ):
        return "CHECKOUT"
    digest = _digest(container)
    if digest and _scan_is_clean(lookup(digest), finding):
        return "SCAN"
    return None


def _linked_containers(finding: Finding):
    return list(HostContainer.objects.filter(repository=finding.repository).select_related("host"))


def verification_rows(finding: Finding, *, github, image_scan_lookup: ImageScanLookup) -> list[dict]:
    """Per-container verification table for the detail panel (and the decision below)."""
    if finding.layer != "APPLICATION" or finding.repository is None:
        return []
    rows = []
    for container in _linked_containers(finding):
        host = container.host
        fresh = bool(finding.pr_merged_at and host.last_seen_at and host.last_seen_at > finding.pr_merged_at)
        rows.append({
            "host": host.hostname,
            "container": container.name,
            "fresh": fresh,
            "proof": _container_proof(finding, container, github, image_scan_lookup) if fresh else None,
            "oci_revision": container.oci_revision,
            "git_head_sha": container.git_head_sha,
            "image_created_at": container.image_created_at,  # hint only
            "pr_merged_at": finding.pr_merged_at,
        })
    return rows


def needs_deployment_decision(finding: Finding) -> bool:
    return (
        finding.layer == "APPLICATION"
        and finding.repository is not None
        and finding.repository.deployment_mode == "UNKNOWN"
        and not HostContainer.objects.filter(repository=finding.repository).exists()
    )


def _verify(finding: Finding, now: datetime, note: str) -> None:
    previous = finding.state
    finding.state = "VERIFIED_LIVE"
    finding.verified_live_at = now
    finding.save()
    log_event(finding, source="SYSTEM", from_state=previous, to_state="VERIFIED_LIVE", note=note, at=now)


def _snapshot(rows: list[dict]) -> list[dict]:
    return [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row.items()} for row in rows]


def _verify_application(finding: Finding, github, lookup, now) -> bool:
    rows = verification_rows(finding, github=github, image_scan_lookup=lookup)
    finding.verification_snapshot = _snapshot(rows)
    finding.verification_checked_at = now
    finding.save(update_fields=["verification_snapshot", "verification_checked_at", "updated_at"])
    if not rows or not all(r["fresh"] and r["proof"] for r in rows):
        return False
    proofs = ", ".join(f"{r['host']}: {r['proof']}" for r in rows)
    _verify(finding, now, f"Live verifiziert ({proofs}). Revision = Image enthält Merge-Commit.")
    return True


def _verify_image(finding: Finding, lookup, now) -> bool:
    image_repo = finding.target_ref.removeprefix("image:")
    containers = [
        c for c in HostContainer.objects.filter(project=finding.project).select_related("host")
        if _digest(c).split("@", 1)[0] == image_repo
    ]
    fresh_since = finding.acknowledged_at or finding.discovered_at
    if not containers or any(not c.host.last_seen_at or c.host.last_seen_at < fresh_since for c in containers):
        return False
    if not all(_scan_is_clean(lookup(_digest(c)), finding) for c in containers):
        return False
    _verify(finding, now, f"Alle laufenden Images ({len(containers)}) ohne die Schwachstelle gescannt.")
    return True


def _verify_infrastructure(finding: Finding, now) -> bool:
    host = finding.host
    if host is None or host.last_seen_at is None:
        return False
    since = finding.acknowledged_at or finding.discovered_at
    if host.last_seen_at <= since:
        return False
    if finding.package_name == "__reboot__":
        if host.reboot_required:
            return False
        _verify(finding, now, "Host meldet keinen ausstehenden Neustart mehr.")
        return True
    if finding.package_name == "__os_eol__":
        if host.os_eol_date and (host.os_eol_date - now.date()).days <= EOL_WARNING_DAYS:
            return False
        _verify(finding, now, f"Host läuft jetzt auf {host.os_distro} {host.os_version}.")
        return True
    if host.reboot_required:
        return False  # kernel/libc updates are only live after a reboot
    if not host.apt_lists_updated_at or now - host.apt_lists_updated_at > APT_LISTS_MAX_AGE:
        return False
    package = host.packages.filter(name=finding.package_name).first()
    if package is None or compare_versions("deb", package.installed_version, finding.target_version) < 0:
        return False
    _verify(finding, now, f"{finding.package_name} {package.installed_version} installiert.")
    return True


def verify_findings(*, github, image_scan_lookup: ImageScanLookup, now: datetime | None = None) -> list[Finding]:
    now = now or timezone.now()
    verified: list[Finding] = []
    for finding in Finding.objects.filter(layer="APPLICATION", state="PR_MERGED_WAITING_LIVE").select_related("repository"):
        if finding.repository is not None and _verify_application(finding, github, image_scan_lookup, now):
            verified.append(finding)
    for finding in Finding.objects.filter(layer="CONTAINER_IMAGE", state__in=("NEW", "IN_PROGRESS")):
        if _verify_image(finding, image_scan_lookup, now):
            verified.append(finding)
    for finding in Finding.objects.filter(layer="INFRASTRUCTURE", state__in=("NEW", "IN_PROGRESS")).select_related("host"):
        if _verify_infrastructure(finding, now):
            verified.append(finding)
    return verified
