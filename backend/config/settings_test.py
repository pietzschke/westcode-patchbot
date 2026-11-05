import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-secret-key-not-for-production-use")

from .settings import *  # noqa: E402,F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
