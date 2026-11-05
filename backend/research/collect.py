"""Candidate collection across repository, container-image and host layers (spec v2.1 §5.2)."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.utils import timezone

from fleet.models import Host, HostContainer
from inventory.models import RepositoryAsset
from research.models import ImageScanCache
from research.scan_runs import record_target
from research.trivy import TrivyResult
from triage.candidates import Candidate, Vuln
from triage.findings import UpsertResult, return_to_work, upsert_finding
from triage.lifecycle import mark_fix_detected_on_branch
from triage.models import Finding
from triage.verification import CONTAINS_MERGE

logger = logging.getLogger(__name__)

IMAGE_CACHE_TTL = timedelta(hours=24)
HOST_DATA_MAX_AGE = timedelta(hours=24)
EOL_WARNING_DAYS = 90
APT_SECURITY_SEVERITY = "HIGH"


@dataclass
class CollectResult:
    created: int = 0
    updated: int = 0
    muted: int = 0
    findings: list[Finding] = field(default_factory=list)
    checkouts: dict = field(default_factory=dict)  # repo full_name -> CheckoutInfo (kept for triage evidence)


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _record_upsert(result: CollectResult, candidate: Candidate, now: datetime) -> UpsertResult:
    outcome = upsert_finding(candidate, now=now)
    if outcome.muted:
        result.muted += 1
    elif outcome.created:
        result.created += 1
    else:
        result.updated += 1
    if not outcome.muted:
        result.findings.append(outcome.finding)
    return outcome


def _branch_contains(github, repo: str, merge_sha: str, head_sha: str) -> bool:
    try:
        return github.compare(repo, merge_sha, head_sha) in CONTAINS_MERGE
    except Exception as exc:  # noqa: BLE001 - unknown relation: leave the finding to live verification
        logger.warning("Compare %s...%s in %s failed: %s", merge_sha, head_sha, repo, exc)
        return False


def _group(vulns: list[dict]) -> dict[tuple[str, str], list[dict]]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for v in vulns:
        grouped[(v["ecosystem"], v["package"])].append(v)
    return grouped


def _candidate(project, layer, target_ref, ecosystem, package, vulns, **extra) -> Candidate:
    return Candidate(
        project=project,
        layer=layer,
        target_ref=target_ref,
        ecosystem=ecosystem,
        package_name=package,
        current_version=vulns[0].get("installed", ""),
        vulns=[Vuln(v["id"], v["severity"], v.get("fixed", "")) for v in vulns],
        **extra,
    )


# --- repositories -------------------------------------------------------------
def _collect_repositories(run, github, trivy, now, result: CollectResult) -> None:
    repos = RepositoryAsset.objects.filter(project__is_monitored=True, is_archived=False).select_related("project")
    for repo in repos:
        target_ref = f"repo:{repo.full_name}"
        started = time.monotonic()
        try:
            checkout = github.checkout(repo.full_name)
        except Exception as exc:  # noqa: BLE001 - any checkout failure is a failed target, never "clean"
            logger.warning("Checkout of %s failed: %s", repo.full_name, exc)
            record_target(run, "REPO", target_ref, TrivyResult("FAILED", str(exc)), duration_ms=_ms(started))
            continue
        result.checkouts[repo.full_name] = checkout
        scan = trivy.scan_repo(repo.full_name, checkout.path)
        record_target(run, "REPO", target_ref, scan, duration_ms=_ms(started))
        if scan.status != "OK":
            continue

        seen: set[tuple[str, str]] = set()
        for (ecosystem, package), vulns in _group(scan.vulnerabilities).items():
            seen.add((ecosystem, package))
            finding = _record_upsert(result, _candidate(repo.project, "APPLICATION", target_ref, ecosystem, package,
                                                        vulns, repository=repo), now).finding
            if (
                finding.state == "PR_MERGED_WAITING_LIVE"
                and finding.merge_commit_sha
                and _branch_contains(github, repo.full_name, finding.merge_commit_sha, checkout.commit_sha)
            ):
                # The default branch already contains the merged fix and still has the CVE → the fix did not work.
                return_to_work(finding, now=now, note=(
                    f"CVE trotz gemergtem Fix ({finding.merge_commit_sha[:12]}) weiterhin auf dem Default-Branch "
                    f"({checkout.commit_sha[:12]})."))

        # A previously open CVE that is gone from the default branch was fixed outside Patchbot's PR flow.
        for finding in Finding.objects.filter(layer="APPLICATION", target_ref=target_ref, state__in=("NEW", "IN_PROGRESS")):
            if (finding.ecosystem, finding.package_name) not in seen:
                mark_fix_detected_on_branch(finding, commit_sha=checkout.commit_sha, now=now)

        repo.last_scanned_at = now
        repo.last_scanned_commit_sha = checkout.commit_sha
        repo.save(update_fields=["last_scanned_at", "last_scanned_commit_sha"])


# --- container images ---------------------------------------------------------
def _scan_image_cached(digest_ref: str, trivy, now: datetime) -> TrivyResult:
    cached = ImageScanCache.objects.filter(image_ref=digest_ref).first()
    if cached and cached.status == "OK" and now - cached.scanned_at < IMAGE_CACHE_TTL:
        return TrivyResult("OK", "", list(cached.vulnerabilities))
    scan = trivy.scan_image(digest_ref)
    ImageScanCache.objects.update_or_create(
        image_ref=digest_ref,
        defaults={"scanned_at": now, "status": scan.status, "vulnerabilities": scan.vulnerabilities},
    )
    return scan


def _collect_images(run, trivy, now, result: CollectResult) -> None:
    containers = HostContainer.objects.filter(project__is_monitored=True).select_related("project", "repository")
    by_digest: dict[str, list[HostContainer]] = defaultdict(list)
    for container in containers:
        digest_ref = next((d for d in container.repo_digests or [] if "@sha256:" in d), "")
        if digest_ref:
            by_digest[digest_ref].append(container)

    for digest_ref, group in by_digest.items():
        image_repo = digest_ref.split("@", 1)[0]
        target_ref = f"image:{image_repo}"
        started = time.monotonic()
        scan = _scan_image_cached(digest_ref, trivy, now)
        record_target(run, "IMAGE", f"image:{digest_ref}", scan, duration_ms=_ms(started))
        if scan.status != "OK":
            continue
        has_source_repo = any(c.repository_id for c in group)
        relevant = [v for v in scan.vulnerabilities if v.get("pkg_class") != "lang-pkgs" or not has_source_repo]
        for project in {c.project for c in group}:
            for (ecosystem, package), vulns in _group(relevant).items():
                _record_upsert(result, _candidate(project, "CONTAINER_IMAGE", target_ref, ecosystem, package, vulns,
                                                  image_ref=digest_ref), now)


# --- hosts ----------------------------------------------------------------------
def _collect_hosts(run, now, result: CollectResult) -> None:
    for host in Host.objects.filter(project__is_monitored=True).select_related("project"):
        target_ref = f"host:{host.slug}"
        if host.last_seen_at is None or now - host.last_seen_at > HOST_DATA_MAX_AGE:
            record_target(run, "HOST", target_ref, TrivyResult("FAILED", "Agent-Daten fehlen oder sind veraltet."))
            continue
        record_target(run, "HOST", target_ref, TrivyResult("OK", ""))
        common = {"project": host.project, "layer": "INFRASTRUCTURE", "target_ref": target_ref, "host": host}

        for pkg in host.packages.filter(is_security_update=True).exclude(candidate_version=""):
            _record_upsert(result, Candidate(
                **common, ecosystem="deb", package_name=pkg.name, current_version=pkg.installed_version,
                vulns=[Vuln(f"apt-security:{pkg.name}", APT_SECURITY_SEVERITY, pkg.candidate_version)],
            ), now)
        if host.reboot_required:
            _record_upsert(result, Candidate(
                **common, ecosystem="host", package_name="__reboot__", current_version=host.kernel_version,
                vulns=[Vuln("REBOOT-REQUIRED", "MEDIUM", "")],
            ), now)
        if host.os_eol_date and (host.os_eol_date - now.date()).days <= EOL_WARNING_DAYS:
            past = host.os_eol_date <= now.date()
            _record_upsert(result, Candidate(
                **common, ecosystem="host", package_name="__os_eol__",
                current_version=f"{host.os_distro} {host.os_version}".strip(),
                vulns=[Vuln(f"OS-EOL:{host.os_distro}-{host.os_version}", "HIGH" if past else "MEDIUM", "")],
            ), now)


def collect_and_upsert(run, *, github, trivy, now: datetime | None = None) -> CollectResult:
    now = now or timezone.now()
    result = CollectResult()
    _collect_repositories(run, github, trivy, now, result)
    _collect_images(run, trivy, now, result)
    _collect_hosts(run, now, result)
    return result
