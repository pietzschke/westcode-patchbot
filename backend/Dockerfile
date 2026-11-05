# syntax=docker/dockerfile:1
# Westcode Patchbot backend image, used by the compose services `web`, `worker` and `trivy-db`.
# Build (context = backend/):  docker compose -f deploy/compose.yaml build web
#
# The worker needs, next to Python/Django:
#   git    – bare mirror cache + worktrees (research.repo_cache)
#   trivy  – repository / image scans (research.trivy, CLI with local DB)
#   npm/uv – deterministic lockfile bumps (research.bumper)
#   docker – CLI only; talks to a daemon only when compose.ai-patching.yaml mounts the socket

FROM ghcr.io/astral-sh/uv:0.11.11 AS uv
FROM aquasec/trivy:0.67.2 AS trivy
FROM docker:28-cli AS dockercli
FROM node:22-trixie-slim AS node

FROM python:3.12-slim-trixie AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.12-slim-trixie
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /usr/local/bin/uv
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
# uid/gid 1000 matches the sandbox user, so worktree files stay writable on both sides. Mount points
# are created here so fresh named volumes inherit the uid 1000 ownership.
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && groupadd --gid 1000 patchbot \
    && useradd --uid 1000 --gid 1000 --home-dir /home/patchbot --create-home --shell /usr/sbin/nologin patchbot \
    && install -d -o 1000 -g 1000 /home/patchbot/.cache /var/lib/patchbot/repo-cache

COPY --from=build /opt/venv /opt/venv
COPY . /app

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DJANGO_SETTINGS_MODULE=config.settings \
    HOME=/home/patchbot \
    TRIVY_CACHE_DIR=/home/patchbot/.cache/trivy \
    UV_CACHE_DIR=/home/patchbot/.cache/uv \
    UV_PYTHON_INSTALL_DIR=/home/patchbot/.cache/uv-python \
    npm_config_cache=/home/patchbot/.cache/npm \
    npm_config_update_notifier=false

LABEL org.opencontainers.image.title="westcode-patchbot-backend" \
      org.opencontainers.image.source="https://github.com/pietzschke/westcode-patchbot"

WORKDIR /app
USER 1000:1000
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "django.core.wsgi:get_wsgi_application()"]
