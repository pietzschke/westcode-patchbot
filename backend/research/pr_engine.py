"""Smart PR handling (spec v2.1 §5.5).

- A Renovate/Dependabot PR that already bumps far enough is reused and gets one
  triage comment (updated in place). Patchbot never pushes to bot branches.
- SIMPLE findings without a bot PR get a deterministic bump in a ready PR.
- COMPLEX findings are handled by the sandboxed code-patching flow (Task 18) or
  left for a human; Claude-written code only ever goes into a Draft-PR.
- Patchbot never merges, approves, or pushes to default branches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from django.utils import timezone

from research.bot_prs import parse_bot_pr
from research.bumper import BumpFailed
from research.diff_gate import DiffRejected, check_diff
from triage.findings import log_event
from triage.models import Finding
from triage.versions import compare_versions

TRIAGE_MARKER = "<!-- patchbot:triage -->"
PR_LABELS = ["patchbot", "security"]
AI_LABEL = "patchbot:ai-generated"
ACTIONABLE_STATES = ("NEW", "IN_PROGRESS")


@dataclass
class PrOutcome:
    action: str  # BOT_REUSED | PR_CREATED | EXISTING | SKIPPED | BUMP_FAILED | PATCH_FAILED | PATCH_REJECTED
    pr_number: int | None = None
    detail: str = ""


def branch_name(finding: Finding) -> str:
    pkg = re.sub(r"[^A-Za-z0-9._-]+", "-", finding.package_name.lstrip("@")).strip("-").lower()
    version = re.sub(r"[^A-Za-z0-9._-]+", "-", finding.target_version)
    return f"patchbot/{pkg}-{version}"


def _create_branch_worktree(worktrees, repo: str, base: str, finding: Finding):
    """Returns (path, branch). The branch may carry a -2, -3, ... suffix when the requested one already exists
    (e.g. an earlier Patchbot PR was closed unmerged); pushing and the PR must use the branch actually created."""
    requested = branch_name(finding)
    created = worktrees.create(repo, base, requested)
    if isinstance(created, tuple):  # BranchCheckout(path, branch)
        return created[0], created[1]
    return created, requested  # providers that only return a path never rename the branch


def render_triage_comment(finding: Finding) -> str:
    lines = [
        "**Westcode Patchbot – Sicherheits-Triage**",
        "",
        f"- Schwachstellen: {', '.join(finding.vulnerability_ids)} (höchster Schweregrad: {finding.highest_severity}"
        + (", **in CISA KEV gelistet**" if finding.kev_listed else "") + ")",
        f"- Paket: `{finding.package_name}` {finding.current_version} → {finding.target_version}",
        f"- Einschätzung: {finding.complexity}" + (f", Erreichbarkeit {finding.reachability}" if finding.reachability else ""),
    ]
    if finding.summary_de:
        lines += ["", finding.summary_de]
    if finding.breaking_changes_de:
        lines += ["", "**Breaking Changes:**", finding.breaking_changes_de]
    if finding.affected_files:
        lines += ["", "**Betroffene Stellen:**"] + [f"- `{f}`" for f in finding.affected_files[:20]]
    lines += ["", "_Automatisch erstellt; Claude-Einschätzungen sind Empfehlungen und ersetzen kein Review._"]
    return "\n".join(lines)


def render_pr_body(finding: Finding) -> str:
    return f"<!-- patchbot:finding:{finding.id} -->\n" + render_triage_comment(finding)


def _record_pr(finding: Finding, *, number: int, url: str, source: str, draft: bool, note: str) -> None:
    finding.pr_number = number
    finding.pr_url = url
    finding.pr_source = source
    finding.pr_is_draft = draft
    finding.save()
    log_event(finding, source="SYSTEM", from_state=finding.state, to_state=finding.state, note=note, at=timezone.now())


def _existing_pr(finding: Finding, github) -> PrOutcome | None:
    if not finding.pr_number:
        return None
    details = github.get_pull(finding.repository.full_name, finding.pr_number)
    if details.get("state") == "open":
        if finding.pr_source == "BOT":
            github.upsert_marker_comment(finding.repository.full_name, finding.pr_number, TRIAGE_MARKER,
                                         render_triage_comment(finding))
        return PrOutcome("EXISTING", finding.pr_number)
    if details.get("merged"):
        return PrOutcome("EXISTING", finding.pr_number, "merged")  # handled by webhook / reconciliation
    old = finding.pr_number
    finding.pr_number, finding.pr_url, finding.pr_source, finding.pr_is_draft = None, "", "", False
    finding.save()
    log_event(finding, source="SYSTEM", from_state=finding.state, to_state=finding.state, at=timezone.now(),
              note=f"PR #{old} wurde ohne Merge geschlossen.")
    return None


def _reuse_bot_pr(finding: Finding, github, *, bumper=None, worktrees=None, patcher=None) -> PrOutcome | None:
    repo = finding.repository.full_name
    for pull in github.list_open_pulls(repo):
        bot = parse_bot_pr(pull)
        if bot is None or bot.package.lower() != finding.package_name.lower():
            continue
        if compare_versions(finding.ecosystem, bot.version, finding.target_version) < 0:
            continue
        github.upsert_marker_comment(repo, bot.number, TRIAGE_MARKER, render_triage_comment(finding))
        _record_pr(finding, number=bot.number, url=bot.html_url, source="BOT", draft=bot.draft,
                   note=f"Bestehenden Bot-PR #{bot.number} übernommen und Triage kommentiert.")
        if finding.complexity == "COMPLEX" and patcher is not None and bot.head_ref:
            # Never push to the bot branch: code changes go into a companion Draft-PR based on it.
            outcome, pr = _ai_patch(finding, github, bumper, worktrees, patcher, base=bot.head_ref, bump=False)
            if pr is not None:
                _log(finding, f"Begleit-Draft-PR #{pr['number']} mit Code-Anpassungen für Bot-PR #{bot.number} erstellt: {pr['html_url']}")
        return PrOutcome("BOT_REUSED", bot.number)
    return None


def _log(finding: Finding, note: str) -> None:
    log_event(finding, source="SYSTEM", from_state=finding.state, to_state=finding.state, note=note, at=timezone.now())


def _ai_patch(finding: Finding, github, bumper, worktrees, patcher, *, base: str, bump: bool):
    """Claude patches code in a sandbox; the diff gate decides; result is always a Draft-PR."""
    repo = finding.repository
    path, branch = _create_branch_worktree(worktrees, repo.full_name, base, finding)
    try:
        if bump:
            try:
                bumper.bump(path, finding.ecosystem, finding.package_name, finding.target_version)
            except BumpFailed as exc:
                _log(finding, f"Automatischer Bump fehlgeschlagen, Code-Anpassung nicht möglich: {exc}")
                return PrOutcome("PATCH_FAILED", detail=str(exc)), None
        result = patcher(finding, path)
        if result.status != "DONE":
            _log(finding, f"Automatische Code-Anpassung nicht abgeschlossen ({result.status}). {result.note}".strip())
            return PrOutcome("PATCH_FAILED", detail=result.status), None
        try:
            check_diff(worktrees.diff(path))
        except DiffRejected as exc:
            _log(finding, f"Code-Anpassung durch Diff-Gate abgelehnt: {exc}")
            return PrOutcome("PATCH_REJECTED", detail=str(exc)), None
        if not worktrees.commit_all(path, f"fix(security): adapt code for {finding.package_name} {finding.target_version}"):
            return PrOutcome("SKIPPED", detail="no changes"), None
        github.push_branch(repo.full_name, branch, path)
        pr = github.create_pull(
            repo.full_name,
            head=branch,
            base=base,
            title=f"[Draft] {finding.package_name} {finding.target_version}: Code-Anpassungen (KI-generiert)",
            body=render_pr_body(finding) + "\n\n> ⚠️ Code von Claude erzeugt – bitte sorgfältig reviewen.",
            draft=True,
            labels=PR_LABELS + [AI_LABEL],
        )
        return PrOutcome("PR_CREATED", pr["number"]), pr
    finally:
        worktrees.release(path)


def _deterministic_pr(finding: Finding, github, bumper, worktrees) -> PrOutcome:
    repo = finding.repository
    path, branch = _create_branch_worktree(worktrees, repo.full_name, repo.default_branch, finding)
    try:
        try:
            bumper.bump(path, finding.ecosystem, finding.package_name, finding.target_version)
        except BumpFailed as exc:
            finding.complexity = "COMPLEX"
            finding.save()
            log_event(finding, source="SYSTEM", from_state=finding.state, to_state=finding.state, at=timezone.now(),
                      note=f"Automatischer Bump fehlgeschlagen, als Komplexer Eingriff eingestuft: {exc}")
            return PrOutcome("BUMP_FAILED", detail=str(exc))
        message = f"fix(deps): bump {finding.package_name} to {finding.target_version}\n\n{', '.join(finding.vulnerability_ids)}"
        if not worktrees.commit_all(path, message):
            return PrOutcome("SKIPPED", detail="bump produced no changes")
        github.push_branch(repo.full_name, branch, path)
        pr = github.create_pull(
            repo.full_name,
            head=branch,
            base=repo.default_branch,
            title=f"fix(deps): {finding.package_name} auf {finding.target_version} ({finding.vulnerability_ids[0] if finding.vulnerability_ids else 'Security'})",
            body=render_pr_body(finding),
            draft=False,
            labels=PR_LABELS,
        )
    finally:
        worktrees.release(path)
    _record_pr(finding, number=pr["number"], url=pr["html_url"], source="PATCHBOT", draft=False,
               note=f"Fix-PR #{pr['number']} erstellt (deterministischer Bump).")
    return PrOutcome("PR_CREATED", pr["number"])


def ensure_pr(finding: Finding, *, github, bumper, worktrees, patcher=None, now=None) -> PrOutcome:
    if finding.layer != "APPLICATION" or finding.repository is None or finding.state not in ACTIONABLE_STATES:
        return PrOutcome("SKIPPED", detail="not actionable")
    existing = _existing_pr(finding, github)
    if existing is not None:
        return existing
    reused = _reuse_bot_pr(finding, github, bumper=bumper, worktrees=worktrees, patcher=patcher)
    if reused is not None:
        return reused
    if finding.complexity == "SIMPLE":
        return _deterministic_pr(finding, github, bumper, worktrees)
    if patcher is None:
        return PrOutcome("SKIPPED", detail="complex fix needs the code-patching sandbox or a human")
    outcome, pr = _ai_patch(finding, github, bumper, worktrees, patcher, base=finding.repository.default_branch, bump=True)
    if pr is not None:
        _record_pr(finding, number=pr["number"], url=pr["html_url"], source="PATCHBOT_AI", draft=True,
                   note=f"Draft-PR #{pr['number']} mit KI-generierten Code-Anpassungen erstellt.")
    return outcome
