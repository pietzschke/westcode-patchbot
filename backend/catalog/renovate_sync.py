import re
from typing import Any
import requests


_RENOVATE_TITLE_RE = re.compile(
    r"(?:update|bump)\s+(?:dependency\s+|docker\s+image\s+)?(?P<dep>[^\s]+)\s+to\s+v?(?P<ver>[^\s]+)",
    re.IGNORECASE,
)


def parse_renovate_pr(
    pr_payload: dict[str, Any],
    repo_full_name: str,
    file_path: str = "",
    ci_status: str = "success",
) -> dict[str, Any] | None:
    """Parse a GitHub Pull Request dictionary from Renovate into a normalized target dict."""
    title = str(pr_payload.get("title") or "")
    match = _RENOVATE_TITLE_RE.search(title)
    if not match:
        return None

    dep = match.group("dep").strip().lower()
    if "/" in dep:
        parts = dep.split("/")
        service_slug = parts[-2] if parts[-1] in {"analytics", "community-edition"} and len(parts) >= 2 else parts[-1]
    else:
        service_slug = dep

    return {
        "service_slug": service_slug,
        "repo_full_name": repo_full_name,
        "file_path": file_path or str(pr_payload.get("file_path") or ""),
        "pr_number": pr_payload.get("number"),
        "pr_url": str(pr_payload.get("html_url") or ""),
        "ci_status": ci_status,
        "target_version": match.group("ver").strip(),
    }


def fetch_open_renovate_prs(
    repos: list[str],
    github_token: str | None = None,
    session: Any = None,
) -> list[dict[str, Any]]:
    """Fetch open Renovate PRs across the given GitHub repositories."""
    http = session or requests
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    results: list[dict[str, Any]] = []
    for repo_full_name in repos:
        resp = http.get(
            f"https://api.github.com/repos/{repo_full_name}/pulls",
            params={"state": "open", "per_page": 100},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        for pr in resp.json():
            user_login = str((pr.get("user") or {}).get("login") or "").lower()
            if "renovate" not in user_login and "renovate" not in str(pr.get("head", {}).get("ref", "")).lower():
                continue
            parsed = parse_renovate_pr(pr, repo_full_name=repo_full_name)
            if parsed is not None:
                results.append(parsed)
    return results
