"""Recognise Renovate/Dependabot pull requests and the version they bump to."""

from __future__ import annotations

import re
from dataclasses import dataclass

BOT_LOGINS = {"renovate[bot]", "dependabot[bot]"}
_DEPENDABOT_RE = re.compile(r"\bbump\s+(?P<dep>\S+)\s+from\s+v?(?P<from>\S+)\s+to\s+v?(?P<ver>[^\s]+)", re.IGNORECASE)
_RENOVATE_RE = re.compile(
    r"\b(?:update|bump)\s+(?:dependency\s+|docker\s+image\s+|module\s+)?(?P<dep>\S+)\s+to\s+v?(?P<ver>[^\s]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class BotPr:
    number: int
    html_url: str
    head_ref: str
    package: str
    version: str
    draft: bool
    from_version: str = ""


def parse_bot_pr(pr: dict) -> BotPr | None:
    if pr.get("user_login") not in BOT_LOGINS:
        return None
    title = str(pr.get("title") or "")
    match = _DEPENDABOT_RE.search(title) or _RENOVATE_RE.search(title)
    if not match:
        return None
    return BotPr(
        number=int(pr["number"]),
        html_url=str(pr.get("html_url") or ""),
        head_ref=str(pr.get("head_ref") or ""),
        package=match.group("dep").strip(),
        version=match.group("ver").strip().rstrip(".,)"),
        draft=bool(pr.get("draft")),
        from_version=(match.groupdict().get("from") or "").strip(),
    )
