"""Minimal Slack Web API client (bot token). Interactivity arrives via the signed webhook."""

from __future__ import annotations

import requests

API = "https://slack.com/api"


class SlackError(Exception):
    pass


class SlackClient:
    def __init__(self, token: str, session=None):
        self.token = token
        self.session = session or requests.Session()

    def _call(self, method: str, http: str = "POST", **payload) -> dict:
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            if http == "GET":
                resp = self.session.get(f"{API}/{method}", headers=headers, params=payload, timeout=15)
            else:
                resp = self.session.post(f"{API}/{method}", headers=headers, json=payload, timeout=15)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            raise SlackError(f"{method}: {exc}") from exc
        if not data.get("ok"):
            raise SlackError(f"{method}: {data.get('error', 'unknown_error')}")
        return data

    def post_message(self, channel: str, text: str, blocks: list[dict] | None = None) -> str:
        """Post to a channel or, with a user id as channel, into the app DM. Returns the message ts."""
        data = self._call("chat.postMessage", channel=channel, text=text, blocks=blocks or [], unfurl_links=False)
        return str(data.get("ts", ""))

    def lookup_user_by_email(self, email: str) -> str | None:
        try:
            data = self._call("users.lookupByEmail", http="GET", email=email)
        except SlackError as exc:
            if "users_not_found" in str(exc):
                return None
            raise
        return (data.get("user") or {}).get("id")
