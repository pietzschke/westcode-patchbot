"""GitHub App authentication and a minimal REST client used by Patchbot.

Write access is deliberately narrow: Patchbot only pushes to ``patchbot/*``
branches (defence in depth next to the org ruleset), never force-pushes,
never merges and never approves.
"""

from __future__ import annotations

import base64
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Protocol

import jwt
import requests

API = "https://api.github.com"
PATCHBOT_BRANCH_PREFIX = "patchbot/"


@dataclass(frozen=True)
class CheckoutInfo:
    path: Path
    commit_sha: str


class GitHubClient(Protocol):
    def list_org_repos(self) -> list[dict]: ...
    def file_exists(self, repo: str, path: str) -> bool: ...
    def checkout(self, repo: str) -> CheckoutInfo: ...
    def list_open_pulls(self, repo: str) -> list[dict]: ...
    def get_pull(self, repo: str, number: int) -> dict: ...
    def compare(self, repo: str, base: str, head: str) -> str: ...
    def upsert_marker_comment(self, repo: str, number: int, marker: str, body: str) -> int: ...
    def create_pull(
        self, repo: str, *, head: str, base: str, title: str, body: str, draft: bool, labels: list[str]
    ) -> dict: ...
    def push_branch(self, repo: str, branch: str, worktree: Path) -> None: ...
    def recent_file_authors(self, repo: str, paths: list[str], since: datetime) -> list[dict]: ...
    def combined_ci_status(self, repo: str, ref: str) -> str: ...


def require_patchbot_branch(branch: str) -> None:
    if not branch.startswith(PATCHBOT_BRANCH_PREFIX) or len(branch) <= len(PATCHBOT_BRANCH_PREFIX):
        raise ValueError(f"Patchbot may only push to {PATCHBOT_BRANCH_PREFIX}* branches, got {branch!r}.")


class GitHubApp:
    """Mints and caches installation access tokens for the westcoder installation."""

    def __init__(self, *, app_id: str, installation_id: str, private_key_pem: bytes | str, session=None):
        self.app_id = app_id
        self.installation_id = installation_id
        self.private_key_pem = private_key_pem
        self.session = session or requests.Session()
        self._token: str | None = None
        self._token_expires_at = 0.0

    def _app_jwt(self) -> str:
        now = int(time.time())
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.app_id}, self.private_key_pem, algorithm="RS256")

    def installation_token(self) -> str:
        if self._token and time.time() < self._token_expires_at - 300:
            return self._token
        resp = self.session.post(
            f"{API}/app/installations/{self.installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {self._app_jwt()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["token"]
        self._token_expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
        return self._token


def _default_runner(argv: list[str], cwd=None, env=None) -> tuple[int, str, str]:
    proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=300)
    return proc.returncode, proc.stdout, proc.stderr


class RestGitHubClient:
    def __init__(
        self,
        *,
        app,
        org: str = "westcoder",
        session=None,
        runner: Callable[..., tuple[int, str, str]] = _default_runner,
        checkout_provider: Callable[[str, "RestGitHubClient"], CheckoutInfo] | None = None,
    ):
        self.app = app
        self.org = org
        self.session = session or requests.Session()
        self.runner = runner
        self.checkout_provider = checkout_provider

    # --- HTTP helpers -------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.app.installation_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, method: str, path_or_url: str, *, json: Any = None, params: dict | None = None):
        url = path_or_url if path_or_url.startswith("http") else f"{API}{path_or_url}"
        return self.session.request(method, url, headers=self._headers(), json=json, params=params, timeout=30)

    def _get_all(self, path: str, params: dict | None = None) -> list[dict]:
        items: list[dict] = []
        url: str | None = path
        query = {"per_page": 100, **(params or {})}
        while url:
            resp = self._request("GET", url, params=query)
            resp.raise_for_status()
            items.extend(resp.json() or [])
            url = (getattr(resp, "links", {}) or {}).get("next", {}).get("url")
            query = None  # the next link already carries the query
        return items

    # --- Protocol -----------------------------------------------------------
    def list_org_repos(self) -> list[dict]:
        return [
            {"full_name": r["full_name"], "default_branch": r.get("default_branch") or "main", "archived": bool(r.get("archived"))}
            for r in self._get_all(f"/orgs/{self.org}/repos", {"type": "all"})
        ]

    def file_exists(self, repo: str, path: str) -> bool:
        resp = self._request("GET", f"/repos/{repo}/contents/{path}")
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True

    def checkout(self, repo: str) -> CheckoutInfo:
        if self.checkout_provider is None:
            raise RuntimeError("No checkout provider configured (see research.repo_cache).")
        return self.checkout_provider(repo, self)

    def list_open_pulls(self, repo: str) -> list[dict]:
        return [
            {
                "number": p["number"],
                "html_url": p.get("html_url", ""),
                "user_login": (p.get("user") or {}).get("login", ""),
                "head_ref": (p.get("head") or {}).get("ref", ""),
                "title": p.get("title", ""),
                "draft": bool(p.get("draft")),
            }
            for p in self._get_all(f"/repos/{repo}/pulls", {"state": "open"})
        ]

    def get_pull(self, repo: str, number: int) -> dict:
        resp = self._request("GET", f"/repos/{repo}/pulls/{number}")
        resp.raise_for_status()
        p = resp.json()
        return {
            "state": p.get("state", ""),
            "merged": bool(p.get("merged")),
            "merged_at": p.get("merged_at"),
            "merge_commit_sha": p.get("merge_commit_sha") or "",
            "draft": bool(p.get("draft")),
            "html_url": p.get("html_url", ""),
        }

    def compare(self, repo: str, base: str, head: str) -> str:
        if base == head:
            return "identical"
        resp = self._request("GET", f"/repos/{repo}/compare/{base}...{head}")
        if resp.status_code == 404:
            return "unknown"
        resp.raise_for_status()
        return str(resp.json().get("status", "unknown"))

    def upsert_marker_comment(self, repo: str, number: int, marker: str, body: str) -> int:
        text = f"{marker}\n{body}"
        for comment in self._get_all(f"/repos/{repo}/issues/{number}/comments"):
            if marker in (comment.get("body") or ""):
                resp = self._request("PATCH", f"/repos/{repo}/issues/comments/{comment['id']}", json={"body": text})
                resp.raise_for_status()
                return int(comment["id"])
        resp = self._request("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": text})
        resp.raise_for_status()
        return int(resp.json()["id"])

    def create_pull(
        self, repo: str, *, head: str, base: str, title: str, body: str, draft: bool, labels: list[str]
    ) -> dict:
        require_patchbot_branch(head)
        resp = self._request(
            "POST", f"/repos/{repo}/pulls", json={"title": title, "head": head, "base": base, "body": body, "draft": draft}
        )
        resp.raise_for_status()
        pr = resp.json()
        if labels:
            self._request("POST", f"/repos/{repo}/issues/{pr['number']}/labels", json={"labels": labels}).raise_for_status()
        return {"number": pr["number"], "html_url": pr.get("html_url", "")}

    def push_branch(self, repo: str, branch: str, worktree: Path) -> None:
        require_patchbot_branch(branch)
        basic = base64.b64encode(f"x-access-token:{self.app.installation_token()}".encode()).decode()
        # Credentials travel via environment-based git config, never via argv (visible in `ps`).
        env = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }
        rc, _, err = self.runner(
            ["git", "push", f"https://github.com/{repo}.git", f"HEAD:refs/heads/{branch}"], cwd=str(worktree), env=env
        )
        if rc != 0:
            raise RuntimeError(f"git push failed for {repo}:{branch}: {err.strip()[:500]}")

    def recent_file_authors(self, repo: str, paths: list[str], since: datetime) -> list[dict]:
        authors: list[dict] = []
        for path in paths:
            for c in self._get_all(f"/repos/{repo}/commits", {"path": path, "since": since.isoformat()}):
                commit_author = (c.get("commit") or {}).get("author") or {}
                authors.append(
                    {
                        "login": (c.get("author") or {}).get("login"),
                        "email": commit_author.get("email", ""),
                        "date": datetime.fromisoformat(commit_author["date"].replace("Z", "+00:00"))
                        if commit_author.get("date")
                        else since,
                    }
                )
        return sorted(authors, key=lambda a: a["date"], reverse=True)

    def combined_ci_status(self, repo: str, ref: str) -> str:
        resp = self._request("GET", f"/repos/{repo}/commits/{ref}/check-runs", params={"per_page": 100})
        resp.raise_for_status()
        runs = resp.json().get("check_runs") or []
        if not runs:
            return "none"
        if any(r.get("conclusion") in {"failure", "cancelled", "timed_out", "action_required"} for r in runs):
            return "failure"
        if any(r.get("status") != "completed" for r in runs):
            return "pending"
        return "success"
