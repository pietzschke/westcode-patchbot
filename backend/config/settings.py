import os
from pathlib import Path

from config.checks import DEV_SECRET_KEY, validate_dev_login, validate_secret_key, validate_tenant_id

BASE_DIR = Path(__file__).resolve().parent.parent

# DEBUG is off unless explicitly enabled; production must provide a real secret key.
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", DEV_SECRET_KEY if DEBUG else "")
validate_secret_key(debug=DEBUG, secret_key=SECRET_KEY)
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",") if h.strip()]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "fleet",
    "inventory",
    "triage",
    "research",
    "controlplane",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

ROOT_URLCONF = "config.urls"

if os.environ.get("POSTGRES_DB"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ["POSTGRES_DB"],
            "USER": os.environ.get("POSTGRES_USER", "patchbot"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", ""),
            "HOST": os.environ.get("POSTGRES_HOST", "db"),
            "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

LANGUAGE_CODE = "de-de"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Sessions, CSRF and API defaults (spec §7.1) ---
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 12 * 60 * 60
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = False  # the Angular client reads csrftoken and sends X-CSRFToken
CSRF_TRUSTED_ORIGINS = [o.strip() for o in os.environ.get("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",") if o.strip()]
# TLS ends at the host reverse proxy, which overwrites X-Forwarded-Proto (runbook §4); web is only bound to
# 127.0.0.1. gunicorn's --forwarded-allow-ips does the same mapping, this keeps is_secure() independent of it.
# Host is passed through unchanged by nginx/Caddy, so USE_X_FORWARDED_HOST is deliberately not enabled.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["inventory.permissions.IsTeamMember"],
}

PATCHBOT_DEV_LOGIN = os.environ.get("PATCHBOT_DEV_LOGIN") or None
validate_dev_login(debug=DEBUG, flag=PATCHBOT_DEV_LOGIN)
PATCHBOT_DEV_LOGIN_ENABLED = DEBUG and PATCHBOT_DEV_LOGIN == "1"

# --- Microsoft Entra ID (single tenant) ---
MICROSOFT_TENANT_ID = os.environ.get("MICROSOFT_TENANT_ID", "")
MICROSOFT_CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")
MICROSOFT_CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
MICROSOFT_REDIRECT_URI = os.environ.get("MICROSOFT_REDIRECT_URI", "")
if MICROSOFT_TENANT_ID:
    validate_tenant_id(MICROSOFT_TENANT_ID)
LOGIN_REDIRECT_URL = "/"

# --- Notion "📂 Projects" database (read-only sync) ---
NOTION_API_KEY = os.environ.get("NOTION_API_KEY", "")
NOTION_PROJECTS_DATABASE_ID = os.environ.get("NOTION_PROJECTS_DATABASE_ID", "41931ab45ea846acbfe46b3305898af2")
NOTION_PROPERTY_NAMES = {
    "title": "Name",
    "status": "Status",
    "owner": "Project Manager",
    "client": "Client",
    "internal": "Intern",
}
NOTION_ACTIVE_STATUSES = ["In progress", "In maintenance"]
NOTION_NOT_STARTED_STATUSES = ["Not started"]
NOTION_CLOSED_STATUSES = ["Done", "GESPERRT!"]

# --- Deadlines (working-day clock, decision D-2) ---
PATCHBOT_TIMEZONE = "Europe/Berlin"
PATCHBOT_HOLIDAY_SUBDIVISION = os.environ.get("PATCHBOT_HOLIDAY_SUBDIVISION", "NW")
PATCHBOT_EXTRA_HOLIDAYS = [d.strip() for d in os.environ.get("PATCHBOT_EXTRA_HOLIDAYS", "").split(",") if d.strip()]

# --- Research / scanning ---
PATCHBOT_REPO_CACHE = Path(os.environ.get("PATCHBOT_REPO_CACHE", BASE_DIR / "var" / "repo-cache"))

# --- Claude triage (spec §5.4) ---
PATCHBOT_CLAUDE_MODEL = os.environ.get("PATCHBOT_CLAUDE_MODEL", "claude-sonnet-5-5")
PATCHBOT_CLAUDE_EFFORT = os.environ.get("PATCHBOT_CLAUDE_EFFORT", "")  # empty = model default
PATCHBOT_CLAUDE_REFUSAL_FALLBACK = os.environ.get("PATCHBOT_CLAUDE_REFUSAL_FALLBACK", "true").lower() == "true"
PATCHBOT_TRIAGE_PROMPT_VERSION = "2026-11-05.1"

# --- Slack ---
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_TEAM_CHANNEL_ID = os.environ.get("SLACK_TEAM_CHANNEL_ID", "")
PATCHBOT_BASE_URL = os.environ.get("PATCHBOT_BASE_URL", "").rstrip("/")

# --- Public webhooks (decision D-1) ---
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")

# --- Worker wiring ---
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_APP_INSTALLATION_ID = os.environ.get("GITHUB_APP_INSTALLATION_ID", "")
GITHUB_APP_PRIVATE_KEY_PATH = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", "")
PATCHBOT_AI_PATCHING = os.environ.get("PATCHBOT_AI_PATCHING", "false").lower() == "true"
