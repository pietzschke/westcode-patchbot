"""Factories for external clients used by request handlers and the worker."""

from __future__ import annotations

from django.conf import settings

from triage.slack import SlackClient, SlackError


class UnconfiguredSlack:
    """Used when SLACK_BOT_TOKEN is missing: every call fails loudly (and is recorded), nothing is silently dropped."""

    def post_message(self, channel, text, blocks=None):
        raise SlackError("Slack ist nicht konfiguriert (SLACK_BOT_TOKEN fehlt).")

    def lookup_user_by_email(self, email):
        raise SlackError("Slack ist nicht konfiguriert (SLACK_BOT_TOKEN fehlt).")


def slack_client():
    return SlackClient(settings.SLACK_BOT_TOKEN) if settings.SLACK_BOT_TOKEN else UnconfiguredSlack()
