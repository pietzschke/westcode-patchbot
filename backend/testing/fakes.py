"""Test doubles for external systems (GitHub, Slack, Anthropic). Extended by later tasks."""

from __future__ import annotations

import tempfile
from pathlib import Path

from inventory.github_app import CheckoutInfo, require_patchbot_branch


class FakeGitHub:
    """In-memory implementation of inventory.github_app.GitHubClient."""

    def __init__(
        self,
        repos=(),
        files=(),
        pulls=None,
        pull_details=None,
        compare=None,
        authors=(),
        head_shas=None,
        ci_status=None,
    ):
        self.repos = list(repos)
        self.files = set(files)
        self.pulls = dict(pulls or {})
        self.pull_details = dict(pull_details or {})
        self.compare_results = dict(compare or {})
        self.authors = list(authors)
        self.head_shas = dict(head_shas or {})
        self.ci_status = dict(ci_status or {})
        self.comments: dict[tuple[str, int], list[str]] = {}
        self.pushes: list[tuple[str, str]] = []
        self.created_pulls: list[dict] = []
        self.author_queries: list[dict] = []
        self.checkouts: list[str] = []
        self._next_pr = 1000

    def list_org_repos(self):
        return list(self.repos)

    def file_exists(self, repo, path):
        return (repo, path) in self.files

    def checkout(self, repo):
        self.checkouts.append(repo)
        return CheckoutInfo(path=Path(tempfile.mkdtemp(prefix="fake-checkout-")), commit_sha=self.head_shas.get(repo, "head"))

    def list_open_pulls(self, repo):
        return list(self.pulls.get(repo, []))

    def get_pull(self, repo, number):
        return dict(self.pull_details.get((repo, number), {"state": "open", "merged": False}))

    def compare(self, repo, base, head):
        if base == head:
            return "identical"
        return self.compare_results.get((repo, base, head), "unknown")

    def upsert_marker_comment(self, repo, number, marker, body):
        bucket = self.comments.setdefault((repo, number), [])
        text = f"{marker}\n{body}"
        for i, existing in enumerate(bucket):
            if marker in existing:
                bucket[i] = text
                return i + 1
        bucket.append(text)
        return len(bucket)

    def create_pull(self, repo, *, head, base, title, body, draft, labels):
        require_patchbot_branch(head)
        self._next_pr += 1
        pr = {"repo": repo, "number": self._next_pr, "html_url": f"https://github.com/{repo}/pull/{self._next_pr}",
              "head": head, "base": base, "title": title, "body": body, "draft": draft, "labels": list(labels)}
        self.created_pulls.append(pr)
        self.pull_details[(repo, pr["number"])] = {"state": "open", "merged": False}
        return {"number": pr["number"], "html_url": pr["html_url"]}

    def push_branch(self, repo, branch, worktree):
        require_patchbot_branch(branch)
        self.pushes.append((repo, branch))

    def recent_file_authors(self, repo, paths, since):
        self.author_queries.append({"repo": repo, "paths": list(paths), "since": since})
        return [a for a in self.authors if a["date"] >= since]

    def combined_ci_status(self, repo, ref):
        return self.ci_status.get((repo, ref), "none")
