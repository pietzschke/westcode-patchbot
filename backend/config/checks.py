"""Startup guards that refuse insecure production configurations."""

from django.core.exceptions import ImproperlyConfigured

DEV_SECRET_KEY = "westcode-patchbot-dev-secret-key"


def validate_secret_key(*, debug: bool, secret_key: str) -> None:
    if debug:
        return
    if not secret_key or secret_key == DEV_SECRET_KEY or len(secret_key) < 32:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY must be set to a random value of at least 32 characters when DEBUG is off."
        )


def validate_dev_login(*, debug: bool, flag: str | None) -> None:
    if flag and not debug:
        raise ImproperlyConfigured("PATCHBOT_DEV_LOGIN is only allowed together with DJANGO_DEBUG=true.")
