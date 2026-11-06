# Runbook: Westcode Patchbot v2 – Deployment und Agent-Rollout

Stand: 2026-11-05 · Spec: `docs/superpowers/specs/2026-11-05-westcode-patchbot-v2-design.md` (§3.3, §5.5, §7, §9, §10)

Dieses Runbook beschreibt, wie Patchbot v2 auf `patch.westcode.de` betrieben wird, welche externen Systeme
eingerichtet werden müssen und in welcher Reihenfolge der neue Host-Agent auf die 23 VMs ausgerollt wird.

> **Dringend:** v1-Agents führen vom Server gelieferte Jobs aus (`compose_update`, `apt_upgrade`,
> `host_reboot`) – als root. Solange irgendwo ein v1-Agent läuft, besteht ein Kanal zur Remote-Ausführung
> auf dieser VM. Die v1-Agents müssen deshalb **zeitnah ersetzt oder wenigstens gestoppt** werden
> (siehe [Abschnitt 11](#11-flotten-rollout-und-rollback)).

## Inhalt

1. [Topologie](#1-topologie)
2. [Server vorbereiten](#2-server-vorbereiten)
3. [Umgebungsvariablen](#3-umgebungsvariablen)
4. [Reverse Proxy und öffentliche Webhooks](#4-reverse-proxy-und-öffentliche-webhooks-d-1)
5. [Slack-App](#5-slack-app)
6. [GitHub App](#6-github-app)
7. [AWS ECR (Leserolle)](#7-aws-ecr-leserolle)
8. [Microsoft Entra ID](#8-microsoft-entra-id)
9. [Notion-Integration](#9-notion-integration)
10. [Inbetriebnahme und Migration von v1](#10-inbetriebnahme-und-migration-von-v1)
11. [Flotten-Rollout und Rollback](#11-flotten-rollout-und-rollback)
12. [Staging-Validierung des Agents](#12-staging-validierung-des-agents)
13. [CI-Anfrage: OCI-Labels](#13-ci-anfrage-oci-labels)
14. [Worker-Docker-Socket](#14-worker-docker-socket)
15. [Lokale Entwicklung](#15-lokale-entwicklung)
16. [Offene Punkte](#16-offene-punkte)

---

## 1. Topologie

`deploy/compose.yaml` (Projektname `patchbot`):

| Dienst | Aufgabe | Netze | Besonderheiten |
|---|---|---|---|
| `postgres` | PostgreSQL 18 | `backend` (internal) | kein Port veröffentlicht, Volume `pgdata` (aus v1 übernommen) |
| `web` | Django/DRF (gunicorn), führt beim Start `migrate` aus | `default`, `backend` | nur `127.0.0.1:8020`, Healthcheck `/api/health/`, read-only, kein Docker-Socket |
| `worker` | `python manage.py run_worker`: Scheduler, Job-Queue, Webhook-Verarbeitung, Trivy, git, npm/uv | `default`, `backend` | Repo-Cache unter `/var/lib/patchbot/repo-cache`, GitHub-App-Key als Compose-Secret; Docker-Socket **nur** mit `compose.ai-patching.yaml` |
| `trivy-db` | aktualisiert alle 6 h die Trivy-DB im Volume `worker-cache` | `default` | gleiches Image wie `worker`; die Scans laufen mit `--skip-db-update` |
| `egress-proxy` | Squid, einziger Ausgang der Sandbox, nur `registry.npmjs.org`, `*.pypi.org`, `files.pythonhosted.org` (HTTPS) | `default`, `patchbot-sandbox-egress` | `deploy/egress-proxy/squid.conf` |
| `renovate` | selbst gehosteter Renovate-Runner aus v1 (unverändert) | `default` | eigene Datei `renovate.env`, sieht die Patchbot-Secrets nicht mehr |

Netze:

- `default`: Bridge mit Internetzugang (GitHub, Slack, Anthropic, Notion, ECR, Entra, Registries).
- `backend` (`internal: true`): nur `postgres`, `web`, `worker`.
- `patchbot-sandbox-egress` (`internal: true`, fester Name): Sandbox-Container plus `egress-proxy`. Ohne
  Proxy gibt es dort weder DNS nach außen noch eine Route ins Internet.

Alle Dienste laufen mit `cap_drop: ALL` und `no-new-privileges`. `web`, `worker` und `trivy-db` laufen als
uid/gid `1000:1000` mit read-only Root-Dateisystem; die Sandbox-Container verwenden dieselbe uid, damit
Worktree-Dateien auf beiden Seiten beschreibbar bleiben.

Die Sandbox-Container (`patchbot-sandbox:node22`, `patchbot-sandbox:python312`) sind keine Compose-Dienste.
Sie werden pro Claude-Patching-Lauf vom Worker über den Docker-Daemon gestartet (`research/sandbox.py`) und
danach wieder entfernt.

## 2. Server vorbereiten

```bash
# Repository-Checkout (Pfad wird in compose.yaml und in diesem Runbook vorausgesetzt)
sudo git clone https://github.com/<org>/westcode-patchbot.git /opt/patchbot
cd /opt/patchbot

# Repo-Cache: Host-Pfad == Container-Pfad (wichtig für die Sandbox-Bind-Mounts), Eigentümer uid 1000
sudo install -d -o 1000 -g 1000 -m 0750 /var/lib/patchbot/repo-cache

# Secrets
sudo install -d -m 0700 deploy/secrets
sudo cp deploy/.env.example deploy/.env && sudo chmod 0600 deploy/.env    # Werte eintragen (Abschnitt 3)
sudo install -m 0600 /dev/null deploy/renovate.env                        # RENOVATE_TOKEN usw. aus der alten .env
sudo install -o 1000 -g 1000 -m 0400 <download>.pem deploy/secrets/github-app.pem

# Images bauen (werden nie aus einer Registry gezogen)
docker compose -f deploy/compose.yaml build

# Frontend bauen: statische Dateien, die der Reverse Proxy (Abschnitt 4) direkt aus
# /opt/patchbot/frontend/dist/frontend/browser ausliefert. Node läuft nur im Wegwerf-Container.
docker run --rm -v /opt/patchbot/frontend:/app -w /app node:22-alpine \
  sh -c 'npm ci --no-audit --no-fund && npx ng build'
ls /opt/patchbot/frontend/dist/frontend/browser/index.html

# Nur für Claude-Code-Patching (Abschnitt 14):
docker build -t patchbot-sandbox:node22    -f deploy/sandbox/Dockerfile.node22    deploy/sandbox
docker build -t patchbot-sandbox:python312 -f deploy/sandbox/Dockerfile.python312 deploy/sandbox
```

`deploy/.env`, `deploy/renovate.env` und `deploy/secrets/` sind über `deploy/.gitignore` ausgeschlossen.
Die `.env` dient nur der Variablen-Interpolation: jeder Dienst bekommt in `compose.yaml` explizit nur die
Variablen, die er braucht (kein `env_file: .env` mehr für `web`/`worker`).

## 3. Umgebungsvariablen

Vorlage: `deploy/.env.example`. „Pflicht“ = `docker compose` bricht ohne Wert ab.

| Variable | Dienst | Pflicht | Bedeutung |
|---|---|---|---|
| `DJANGO_SECRET_KEY` | web, worker | ja | Zufallswert ≥ 32 Zeichen (`python -c "import secrets; print(secrets.token_urlsafe(50))"`). Der Start schlägt bei DEBUG=false sonst fehl. |
| `DJANGO_DEBUG` | web, worker | – | in Compose fest `false`. `true` nur lokal. |
| `DJANGO_ALLOWED_HOSTS` | web | ja | `patch.westcode.de` (kommagetrennt; der erste Eintrag wird auch für den Healthcheck verwendet). |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | web | ja | `https://patch.westcode.de` |
| `POSTGRES_PASSWORD` | postgres, web, worker | ja | DB-Passwort. `POSTGRES_DB`/`POSTGRES_USER` sind fest `patchbot`, `POSTGRES_HOST=postgres`, `POSTGRES_PORT=5432`. |
| `PATCHBOT_BASE_URL` | web, worker | ja | `https://patch.westcode.de` – für Links in Slack-Nachrichten. |
| `MICROSOFT_TENANT_ID` | web | ja | Tenant-GUID (kein `common`/`organizations`, sonst Startabbruch). |
| `MICROSOFT_CLIENT_ID` | web | ja | Application (client) ID der App-Registrierung. |
| `MICROSOFT_CLIENT_SECRET` | web | ja | Client Secret (Ablaufdatum im Kalender vermerken). |
| `MICROSOFT_REDIRECT_URI` | web | ja | `https://patch.westcode.de/api/auth/entra/callback/` |
| `SLACK_SIGNING_SECRET` | web | ja | Prüft jede Slack-Interaktion (HMAC, max. 5 min alt). Ohne Wert wird alles mit 401 abgelehnt. |
| `GITHUB_WEBHOOK_SECRET` | web | ja | Prüft `X-Hub-Signature-256`. Ohne Wert wird alles mit 401 abgelehnt. |
| `SLACK_BOT_TOKEN` | web, worker | nein | `xoxb-…`. Ohne Token keine DMs/Posts (der Worker loggt das). |
| `SLACK_TEAM_CHANNEL_ID` | web, worker | nein | Kanal für Transparenz-Posts und Eskalationen (`C…`). |
| `GITHUB_APP_ID` | worker | ja | App ID der GitHub App. |
| `GITHUB_APP_INSTALLATION_ID` | worker | ja | Installation ID in der Org `westcoder`. |
| `GITHUB_APP_PRIVATE_KEY_PATH` | worker | – | fest `/run/secrets/github_app_private_key` (Datei `deploy/secrets/github-app.pem`). |
| `ANTHROPIC_API_KEY` | worker | nein | Ohne Key bleiben Findings `UNTRIAGED`, kein Patching. |
| `PATCHBOT_CLAUDE_MODEL` | worker | nein | Default `claude-sonnet-5-5`. |
| `PATCHBOT_CLAUDE_EFFORT` | worker | nein | leer = Modell-Default. |
| `PATCHBOT_CLAUDE_REFUSAL_FALLBACK` | worker | nein | Default `true`. |
| `NOTION_API_KEY` | worker | nein | Ohne Key wird der Notion-Sync übersprungen. |
| `NOTION_PROJECTS_DATABASE_ID` | worker | nein | Default `41931ab45ea846acbfe46b3305898af2` („📂 Projects“). |
| `PATCHBOT_HOLIDAY_SUBDIVISION` | web, worker | nein | Feiertage für Arbeitstagsfristen, Default `NW`. |
| `PATCHBOT_EXTRA_HOLIDAYS` | web, worker | nein | zusätzliche freie Tage, `YYYY-MM-DD,YYYY-MM-DD`. |
| `PATCHBOT_REPO_CACHE` | worker | – | fest `/var/lib/patchbot/repo-cache` (muss dem Host-Pfad entsprechen). |
| `PATCHBOT_AI_PATCHING` | worker | – | `false`; nur `compose.ai-patching.yaml` setzt `true`. |
| `AWS_REGION` | worker | nein | Default `eu-central-1`, für ECR-Image-Scans. |
| `DOCKER_GID` | worker | nur mit AI-Patching | Gruppen-ID von `/var/run/docker.sock` (`stat -c %g /var/run/docker.sock`). |
| `PATCHBOT_DEV_LOGIN` | – | – | **nie in Produktion.** Nur lokal zusammen mit `DJANGO_DEBUG=true`; sonst Startabbruch. |

Slack läuft ausschließlich über HTTP-Interaktivität: es gibt **kein `SLACK_APP_TOKEN`** (kein Socket Mode).

`deploy/renovate.env` (nur für den Dienst `renovate`): `RENOVATE_TOKEN`, `CODEARTIFACT_AUTH_TOKEN` und
gegebenenfalls weitere `RENOVATE_*`-Werte aus der bisherigen `.env`.

## 4. Reverse Proxy und öffentliche Webhooks (D-1)

Ins Internet dürfen **nur** diese zwei Routen, jeweils nur `POST`, mit 1 MB Body-Limit und Rate-Limit:

- `POST /api/webhooks/slack/interactions/`
- `POST /api/webhooks/github/`

Alles andere ist nur aus internen Netzen erreichbar, mit **zwei getrennten Allowlists**:

- **Büro/VPN** (`patchbot-internal.conf` bzw. `@internal`): Frontend, `/api/…`, Entra-Login. Keine VM-IPs.
- **Egress-IPs der 23 VMs** (`patchbot-agents.conf` bzw. `@agent`): ausschließlich
  `POST /api/agent/report/`. Eine VM erreicht damit weder das UI noch andere API-Pfade.

Der Entra-Callback braucht keine öffentliche Erreichbarkeit – er wird vom Browser des Nutzers aufgerufen.

### nginx (Beispiel)

```nginx
# /etc/nginx/conf.d/patchbot.conf
limit_req_zone $binary_remote_addr zone=patchbot_webhooks:10m rate=10r/s;

upstream patchbot_web {
    server 127.0.0.1:8020;
}

server {
    listen 443 ssl;
    http2 on;
    server_name patch.westcode.de;
    # ssl_certificate / ssl_certificate_key …

    client_max_body_size 1m;
    # Achtung: proxy_set_header wird nicht vererbt, sobald eine location eigene Header setzt –
    # daher steht der Block in jeder location (Snippet patchbot-proxy.conf).

    # --- öffentlich: genau zwei Webhook-Pfade, nur POST ---
    location = /api/webhooks/slack/interactions/ {
        limit_except POST { deny all; }
        limit_req zone=patchbot_webhooks burst=20 nodelay;
        include /etc/nginx/snippets/patchbot-proxy.conf;
        proxy_set_header Cookie "";          # Webhooks akzeptieren keine Session-Cookies
        proxy_read_timeout 10s;
        proxy_pass http://patchbot_web;
    }
    location = /api/webhooks/github/ {
        limit_except POST { deny all; }
        limit_req zone=patchbot_webhooks burst=20 nodelay;
        include /etc/nginx/snippets/patchbot-proxy.conf;
        proxy_set_header Cookie "";
        proxy_read_timeout 10s;
        proxy_pass http://patchbot_web;
    }

    # --- Agent-VMs: genau ein Pfad, nur POST, eigene Allowlist ---
    location = /api/agent/report/ {
        include /etc/nginx/snippets/patchbot-agents.conf;
        limit_except POST { deny all; }
        include /etc/nginx/snippets/patchbot-proxy.conf;
        proxy_set_header Cookie "";          # Agent authentifiziert sich nur per Bearer-Token
        proxy_pass http://patchbot_web;
    }

    # --- intern (Büro/VPN): UI und restliche API ---
    location /api/ {
        include /etc/nginx/snippets/patchbot-internal.conf;
        include /etc/nginx/snippets/patchbot-proxy.conf;
        proxy_pass http://patchbot_web;
    }
    location / {
        include /etc/nginx/snippets/patchbot-internal.conf;
        root /opt/patchbot/frontend/dist/frontend/browser;   # Build: Abschnitt 2
        try_files $uri /index.html;
    }
}
```

```nginx
# /etc/nginx/snippets/patchbot-proxy.conf
proxy_set_header Host              $host;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
```

```nginx
# /etc/nginx/snippets/patchbot-internal.conf  (UI + API: nur Menschen)
allow 10.0.0.0/8;         # Büro/VPN – anpassen
deny all;
```

```nginx
# /etc/nginx/snippets/patchbot-agents.conf  (nur POST /api/agent/report/)
allow 203.0.113.10;       # Egress-IP je Agent-VM – eine Zeile pro VM
deny all;
```

### Caddy (Alternative)

```caddyfile
{
    order rate_limit before basic_auth
}

patch.westcode.de {
    request_body {
        max_size 1MB
    }

    @webhooks {
        method POST
        path /api/webhooks/slack/interactions/ /api/webhooks/github/
    }
    handle @webhooks {
        # Rate-Limit benötigt das Plugin caddy-ratelimit (xcaddy build --with github.com/mholt/caddy-ratelimit)
        rate_limit {
            zone webhooks {
                key    {remote_host}
                events 600
                window 1m
            }
        }
        request_header -Cookie
        reverse_proxy 127.0.0.1:8020
    }

    # Agent-VMs: nur dieser eine Pfad, nur POST
    @agent {
        method POST
        path /api/agent/report/
        remote_ip 203.0.113.10   # Egress-IPs der Agent-VMs (leerzeichengetrennt)
    }
    handle @agent {
        request_header -Cookie
        reverse_proxy 127.0.0.1:8020
    }

    @internal remote_ip 10.0.0.0/8   # nur Büro/VPN – keine VM-IPs
    handle @internal {
        handle /api/* {
            reverse_proxy 127.0.0.1:8020
        }
        handle {
            root * /opt/patchbot/frontend/dist/frontend/browser   # Build: Abschnitt 2
            try_files {path} /index.html
            file_server
        }
    }

    handle {
        respond 404
    }
}
```

Prüfung von außen (aus einem Netz, das **nicht** auf der Allowlist steht):

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://patch.westcode.de/api/webhooks/github/   # 401 (Signatur fehlt)
curl -s -o /dev/null -w '%{http_code}\n' https://patch.westcode.de/api/webhooks/github/           # 403/405 (kein POST)
curl -s -o /dev/null -w '%{http_code}\n' https://patch.westcode.de/api/health/                    # 403/404
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://patch.westcode.de/api/agent/report/      # 403/404
head -c 2000000 /dev/zero | curl -s -o /dev/null -w '%{http_code}\n' -X POST --data-binary @- \
  https://patch.westcode.de/api/webhooks/github/                                                  # 413
```

Prüfung von einer Agent-VM aus (deren Egress-IP auf der Agent-Allowlist steht):

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://patch.westcode.de/api/agent/report/      # 401 (Token fehlt)
curl -s -o /dev/null -w '%{http_code}\n' https://patch.westcode.de/api/agent/report/              # 403/404 (kein POST)
curl -s -o /dev/null -w '%{http_code}\n' https://patch.westcode.de/api/hosts/                     # 403/404
curl -s -o /dev/null -w '%{http_code}\n' https://patch.westcode.de/                               # 403/404
```

## 5. Slack-App

Unter <https://api.slack.com/apps> → „Create New App“ → „From a manifest“:

```yaml
display_information:
  name: Westcode Patchbot
features:
  bot_user:
    display_name: Patchbot
    always_online: false
oauth_config:
  scopes:
    bot:
      - chat:write
      - users:read
      - users:read.email
      - im:write
settings:
  interactivity:
    is_enabled: true
    request_url: https://patch.westcode.de/api/webhooks/slack/interactions/
  socket_mode_enabled: false
  org_deploy_enabled: false
  token_rotation_enabled: false
```

1. App im Westcode-Workspace installieren → „Bot User OAuth Token“ (`xoxb-…`) = `SLACK_BOT_TOKEN`.
2. „Basic Information“ → „Signing Secret“ = `SLACK_SIGNING_SECRET`.
3. Keine Event Subscriptions, kein Socket Mode, kein App-Level-Token.
4. Bot in den Team-Kanal einladen (`/invite @Patchbot`), Kanal-ID = `SLACK_TEAM_CHANNEL_ID`.
5. Test: im UI unter „Team“ eine Test-DM auslösen; Buttons in der DM müssen ein 200 liefern (Slack zeigt
   sonst eine Fehlermeldung am Button). Unbekannte Slack-Nutzer werden abgewiesen – `slack_user_id` wird über
   `users.lookupByEmail` automatisch gesetzt.

## 6. GitHub App

Org `westcoder` → Settings → Developer settings → GitHub Apps → „New GitHub App“:

- **Name:** `westcode-patchbot`, **Homepage:** `https://patch.westcode.de`
- **Webhook:** aktiv, URL `https://patch.westcode.de/api/webhooks/github/`, Secret = `GITHUB_WEBHOOK_SECRET`
  (`openssl rand -hex 32`), SSL-Verifizierung an.
- **Repository permissions:**
  - Contents: **Read and write** (Pushes werden per Ruleset auf `patchbot/*` begrenzt, s. u.)
  - Pull requests: **Read and write** (PRs anlegen, Kommentare, Labels)
  - Checks: **Read-only** (CI-Status der PRs)
  - Metadata: **Read-only** (Pflicht)
  - **Workflows: keine** · **Administration: keine** · alles andere: keine
- **Events abonnieren:** `Pull request`, `Check suite`
- **Where can this app be installed:** „Only on this account“

Danach:

1. Private Key erzeugen → `deploy/secrets/github-app.pem` (uid 1000, Modus 0400). App ID = `GITHUB_APP_ID`.
2. In `westcoder` installieren mit **„Only select repositories“** – alle Projekt-Repositories, **ohne
   `westcode-infra`** (D-5). Neue Repositories müssen der Installation manuell hinzugefügt werden.
   Installation ID (aus der URL `…/installations/<id>`) = `GITHUB_APP_INSTALLATION_ID`.
3. **Org-Ruleset** „Patchbot nur auf patchbot/*“ (Org → Settings → Repository → Rulesets → New branch ruleset):
   - Target: alle Repositories; Branches: Include `~ALL`, Exclude `refs/heads/patchbot/**`
   - Rules: „Restrict creations“, „Restrict updates“, „Restrict deletions“
   - Bypass list: die Rollen/Teams/Apps, die heute auf diese Branches pushen dürfen (Repository-Rollen
     Write/Maintain/Admin, Renovate, Dependabot, CI-Integrationen) – **nicht** `westcode-patchbot`.
   - Ergebnis: Patchbot kann ausschließlich `patchbot/*` anlegen und aktualisieren; Default-Branches und
     Bot-Branches sind für die App gesperrt.
   - Vorsicht: Das Ruleset betrifft jeden Akteur, der nicht auf der Bypass-Liste steht. Vor dem Aktivieren
     prüfen, welche Integrationen pushen; zuerst auf einem Test-Repository ausprobieren.
4. Prüfen: mit einem Installation-Token einen Push auf `main` eines Test-Repos versuchen → muss scheitern;
   Push auf `patchbot/test` → muss klappen; Zugriff auf `westcoder/westcode-infra` → 404.

Hinweis: Patchbot liest CI-Ergebnisse über die Checks-API. Reporten Projekte ihren CircleCI-Status nur als
Commit-Status (alte OAuth-Integration), erscheint dort kein CI-Status (siehe [Offene Punkte](#16-offene-punkte)).

## 7. AWS ECR (Leserolle)

Der Worker scannt laufende Images per `trivy image --image-src remote <repo>@<digest>`. Trivy nutzt die
AWS-Default-Credential-Chain.

IAM-Rolle `patchbot-ecr-read` mit genau dieser Policy (Konto `533267181938`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*" },
    {
      "Effect": "Allow",
      "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
      "Resource": "arn:aws:ecr:eu-central-1:533267181938:repository/*"
    }
  ]
}
```

Anbindung je nach Hosting des Patchbot-Servers:

- **EC2:** Rolle als Instance Profile anhängen. Damit Container IMDSv2 erreichen, das Hop-Limit auf 2 setzen:
  `aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-put-response-hop-limit 2`.
- **Außerhalb von AWS:** IAM-User `patchbot-ecr` mit nur `sts:AssumeRole` auf `patchbot-ecr-read`, Profil
  per Override einbinden (Datei `deploy/compose.aws.yaml`, mit `-f` zusätzlich angeben):

  ```yaml
  services:
    worker:
      environment:
        AWS_CONFIG_FILE: /run/secrets/aws_config
        AWS_SHARED_CREDENTIALS_FILE: /run/secrets/aws_credentials
        AWS_PROFILE: patchbot-ecr
      secrets: [aws_config, aws_credentials]
  secrets:
    aws_config:      { file: ./secrets/aws-config }       # [profile patchbot-ecr] role_arn=… source_profile=patchbot-ecr-user
    aws_credentials: { file: ./secrets/aws-credentials }  # [patchbot-ecr-user] aws_access_key_id=…
  ```

Prüfen: `docker compose -f deploy/compose.yaml exec worker trivy image --image-src remote --skip-db-update --quiet <ecr-image>@sha256:…`.

## 8. Microsoft Entra ID

Entra Admin Center → App registrations → „New registration“:

- **Name:** Westcode Patchbot
- **Supported account types:** „Accounts in this organizational directory only“ (Single Tenant)
- **Redirect URI:** Plattform „Web“, `https://patch.westcode.de/api/auth/entra/callback/`
- Certificates & secrets → neues Client Secret → `MICROSOFT_CLIENT_SECRET` (Ablauf notieren, rechtzeitig rotieren)
- API permissions: Microsoft Graph, delegiert: `openid`, `profile`, `email` (Standard, keine Admin-Zustimmung nötig)
- Token configuration: optionalen Claim `email` für das ID-Token hinzufügen
- Empfohlen: Enterprise Application → Properties → „Assignment required“ = Ja und nur das Team zuweisen
  (zusätzlich zur Prüfung gegen `TeamMember` in Patchbot)

Werte: Directory (tenant) ID → `MICROSOFT_TENANT_ID`, Application (client) ID → `MICROSOFT_CLIENT_ID`.
Der erste Login bindet über die E-Mail (`@westcode.de`) an einen aktiven `TeamMember` und speichert die `oid`;
ohne passenden `TeamMember` wird der Login abgewiesen.

## 9. Notion-Integration

<https://www.notion.so/my-integrations> → „New integration“ (intern, Workspace Westcode):

- Capabilities: **Read content** – *nicht* Update/Insert content, keine Kommentare
- User capabilities: **„Read user information including email addresses“** (für `Project Manager` → `TeamMember`)
- Internal Integration Secret → `NOTION_API_KEY`
- Die Datenbank **„📂 Projects“** mit der Integration teilen (Datenbank → `•••` → Connections → Integration
  hinzufügen). Für den Kundennamen (`Client`-Relation) muss auch die verknüpfte Kunden-Datenbank geteilt sein.

Prüfen: im UI „Projekte & Zuordnung“ → Notion-Sync starten; unbekannte Status-Werte erscheinen im Sync-Ergebnis.

## 10. Inbetriebnahme und Migration von v1

v1 lief mit den Diensten `db`, `trivy`, `backend`, `renovate`. In v2 heißt die Datenbank `postgres`
(dasselbe Volume `pgdata`), `backend` wird zu `web` + `worker`, der Trivy-Server entfällt.

```bash
cd /opt/patchbot
C="docker compose -f deploy/compose.yaml"

# 1. Backup der v1-Datenbank (alter Dienstname: db)
$C exec -T db pg_dump -U patchbot -Fc patchbot > /root/patchbot-v1-$(date +%F).dump

# 2. Code aktualisieren, .env/renovate.env/secrets wie in Abschnitt 2 und 3 anlegen
git fetch && git checkout <v2-release>

# 3. Bauen und starten; --remove-orphans entfernt die alten Container db, backend, trivy
$C build
$C up -d --remove-orphans
# Frontend neu bauen (der Reverse Proxy liefert dist/frontend/browser aus, siehe Abschnitt 2)
docker run --rm -v /opt/patchbot/frontend:/app -w /app node:22-alpine \
  sh -c 'npm ci --no-audit --no-fund && npx ng build'
docker volume rm patchbot_trivy-cache        # Cache des alten Trivy-Servers

# 4. Kontrolle
$C ps                                        # web healthy, worker/trivy-db/egress-proxy running
curl -s -H 'Host: patch.westcode.de' http://127.0.0.1:8020/api/health/   # {"status":"ok"}
$C logs --tail 50 worker trivy-db
```

Danach:

1. Reverse Proxy umstellen (Abschnitt 4) und die Prüfungen von außen durchführen.
2. **Ersten Admin per CLI anlegen (Bootstrap).** Der Entra-Login akzeptiert nur Personen, die bereits als
   aktives Teammitglied existieren, und Teammitglieder kann im UI nur ein Admin anlegen. Auf einer frischen
   Datenbank deshalb den ersten Admin (idempotent, nur `@westcode.de`) per Management-Command anlegen:

   ```bash
   $C exec web python manage.py create_team_admin \
     --email vorname.nachname@westcode.de --name "Vorname Nachname" --default-infra-owner
   ```

   Danach mit diesem Konto den Entra-Login testen und die übrigen Teammitglieder im UI („Team“) anlegen –
   mindestens ein Admin, genau ein Default-Infra-Owner (`--default-infra-owner` weglassen, falls dieser
   jemand anderes sein soll; ein zweiter aktiver Default-Infra-Owner wird abgelehnt).
3. Notion-Sync, Repository-Sync und einen ersten Scan („Scan & Sync starten“) auslösen. Bis die Trivy-DB
   geladen ist (`trivy-db`-Logs), enden Scans als FAILED (Ampel GRAU) – nie fälschlich grün.
4. **Hosts importieren.** Im UI lassen sich Hosts nicht anlegen; die Host-Liste kommt aus dem
   `westcode-infra`-Checkout (`stacks/*/servers.tf`). Der Checkout muss für uid 1000 lesbar sein:

   ```bash
   sudo git clone https://github.com/<org>/westcode-infra.git /opt/westcode-infra   # bzw. git pull
   $C run --rm --no-deps -v /opt/westcode-infra:/infra:ro web python manage.py sync_infra_hosts /infra
   ```

   Den Import nach Änderungen an `servers.tf` wiederholen. Er legt Hosts an bzw. aktualisiert Provider,
   Stack und deklariertes Image; vom Agenten gemeldete OS-Daten überschreibt er nicht.
5. **Agent-Tokens erzeugen** (Admin): im UI „Live-Hosts“ → Host → „Agent-Token generieren“ (bzw.
   `POST /api/hosts/<slug>/token/`). Die Antwort enthält das Token einmalig und den fertigen
   `install-agent.sh`-Aufruf für Abschnitt 11.

Rollback des Servers: auf den vorherigen v2-Stand zurück (`git checkout <vorheriger-tag>`, `build`, `up -d`,
Frontend-Build),
bei Schema-Problemen das Backup mit `pg_restore --clean` einspielen. **v1 ist kein Rollback-Ziel**: der
v1-Server würde den Job-Kanal zu den Agents wieder öffnen.

## 11. Flotten-Rollout und Rollback

Voraussetzungen: v2-Server läuft, Agent-Endpunkt `/api/agent/report/` ist von den VMs erreichbar (Agent-Allowlist
`patchbot-agents.conf` bzw. `@agent` im Reverse Proxy), pro Host existiert ein Token, die Staging-Validierung (Abschnitt 12) ist bestanden.

### Sofortmaßnahme gegen v1-Agents

Der v1-Agent lief als Dauerdienst (`Restart=always`) und pollte Jobs, die er als root ausführte. Der
v2-Server bietet diese Endpunkte nicht mehr an, aber jeder, der sich als Server ausgeben kann (DNS, Proxy,
versehentlicher v1-Rollback), könnte darüber Befehle ausführen. Wenn der v2-Agent nicht sofort auf allen VMs
installiert werden kann, den v1-Agent vorab stoppen:

```bash
sudo systemctl disable --now westcode-patchbot-agent.service
```

### Reihenfolge

1. **Staging-VM** – vollständige Validierung (Abschnitt 12).
2. **Welle 1:** 2–3 interne/unkritische VMs, 24 h beobachten (alle 15 min ein Report, keine Fehler im Journal,
   Container- und Paketlisten plausibel).
3. **Wellen 2–n:** je ca. 5–6 VMs pro Tag, Kunden-Produktivsysteme zuletzt.
4. Nach allen 23 VMs: Live-Verifikation aktivieren (Spec §9 Schritt 5). Hosts mit altem Agent gelten bis
   dahin als veraltet (Ampel GRAU).
5. Danach D-4 neu bewerten (read-only Docker-Socket-Proxy auf den VMs).

### Installation pro VM

```bash
# Repository-Kopie mit agent/ und deploy/ auf der VM, Token aus dem Patchbot-UI
# (das Skript stoppt und deaktiviert einen laufenden v1-Daemon, bevor es Binary und Units ersetzt)
sudo PATCHBOT_TOKEN='<token>' PATCHBOT_URL='https://patch.westcode.de' ./deploy/install-agent.sh

# Kontrolle
pgrep -af westcode-patchbot-agent                   # kein Dauerprozess (v1-Daemon beendet)
systemctl list-unit-files 'westcode-patchbot*'      # .service = static, .timer = enabled
systemctl list-timers westcode-patchbot-agent.timer
grep -m1 AGENT_VERSION /usr/local/libexec/westcode-patchbot-agent   # "2.0.0"
sudo systemctl start westcode-patchbot-agent.service && journalctl -u westcode-patchbot-agent -n 20 --no-pager
systemctl list-unit-files | grep -i patchbot        # keine weiteren (v1-)Units
```

Im UI unter „Live-Hosts“: `last_seen_at` aktuell, Agent-Version 2.0.0, Container mit Digest.

### Rollback (Agent)

Der v2-Agent ist read-only und führt nichts aus, was vom Server kommt. Rollback heißt deshalb nur
„Reporting stoppen“:

```bash
sudo systemctl disable --now westcode-patchbot-agent.timer
```

**Niemals den v1-Agent wieder installieren.** Bei kompromittiertem Token: im UI neues Token erzeugen
(das alte wird ungültig) und `/etc/westcode-patchbot/agent.env` aktualisieren.

## 12. Staging-Validierung des Agents

Ziel: nachweisen, dass alle Lesebefehle unter den Restriktionen der Unit funktionieren (`ProtectSystem=strict`,
`ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, `ReadOnlyPaths=/opt`).

```bash
P="-p ProtectSystem=strict -p ProtectHome=true -p PrivateTmp=true -p NoNewPrivileges=true -p ReadOnlyPaths=/opt"

# Einzelbefehle mit identischer Sandbox
sudo systemd-run --wait --pipe --collect $P apt-get -s dist-upgrade | grep -c '^Inst'
sudo systemd-run --wait --pipe --collect $P dpkg-query -W -f='${Package}\t${Version}\n' | wc -l
sudo systemd-run --wait --pipe --collect $P docker ps -q
sudo systemd-run --wait --pipe --collect $P sh -c 'docker inspect $(docker ps -q) --format "{{.Name}} {{.Image}} {{index .Config.Labels \"org.opencontainers.image.revision\"}}"'
sudo systemd-run --wait --pipe --collect $P -p WorkingDirectory=/opt/<app> git -c safe.directory=/opt/<app> rev-parse HEAD
sudo systemd-run --wait --pipe --collect $P -p WorkingDirectory=/opt/<app> git -c safe.directory=/opt/<app> status --porcelain

# Gesamte Erhebung ohne Senden
sudo systemd-run --wait --pipe --collect $P /usr/bin/python3 /usr/local/libexec/westcode-patchbot-agent --collect-json \
  | python3 -m json.tool | less
```

Checkliste:

- [ ] `apt-get -s` liefert `Inst`-Zeilen (Warnungen zu `pkgcache.bin` wegen read-only `/var/cache/apt` sind
      unkritisch, ein Abbruch nicht).
- [ ] `dpkg-query` liefert die vollständige Paketliste.
- [ ] `docker ps`/`docker inspect` funktionieren (Socket-Zugriff unter `ProtectSystem=strict`; eine Warnung
      zu `/root/.docker/config.json` wegen `ProtectHome` ist unkritisch).
- [ ] `git rev-parse HEAD` und `git status --porcelain` funktionieren für `/opt`-Checkouts fremder Eigentümer.
- [ ] `--collect-json` enthält `os_*`, `kernel_version`, `reboot_required`, `apt_lists_updated_at`, Pakete
      und Container mit `repo_digests`.
- [ ] Echter Lauf (`systemctl start westcode-patchbot-agent.service`) endet mit Exit 0, der Host erscheint im UI.
- [ ] Laufzeit deutlich unter `TimeoutStartSec=300`.

Scheitert ein Punkt, wird die Unit **nicht** gelockert, sondern der Agent angepasst (z. B. apt-Cache-Optionen,
`GIT_OPTIONAL_LOCKS=0`) und erneut validiert.

## 13. CI-Anfrage: OCI-Labels

Die Live-Verifikation beweist am besten über die Labels `org.opencontainers.image.revision` (Commit-SHA) und
`org.opencontainers.image.source` (Repository-URL), dass ein Fix wirklich läuft. Ohne Labels fällt Patchbot
auf den Scan-Nachweis (c) zurück. Textvorschlag für die Projekt-Teams:

> Bitte setzt beim Image-Build die OCI-Labels `org.opencontainers.image.revision` und
> `org.opencontainers.image.source`. Mit `docker/metadata-action` passiert das automatisch. In CircleCI:
>
> ```bash
> docker build \
>   --label org.opencontainers.image.revision="$CIRCLE_SHA1" \
>   --label org.opencontainers.image.source="https://github.com/westcoder/$CIRCLE_PROJECT_REPONAME" \
>   …
> ```
>
> Prüfen: `docker image inspect <image> --format '{{json .Config.Labels}}'`

Das `source`-Label verknüpft Container und Repository außerdem automatisch (deterministischer Auto-Match).

## 14. Worker-Docker-Socket

Für Claude-Code-Patching (`COMPLEX`-Findings → Draft-PR) startet der Worker pro Lauf einen Sandbox-Container.
Dafür braucht er den Docker-Socket des Servers:

```bash
docker compose -f deploy/compose.yaml -f deploy/compose.ai-patching.yaml up -d
```

**Risiko:** Zugriff auf `/var/run/docker.sock` ist root-äquivalent auf dem Patchbot-Server (z. B. `docker run
-v /:/host …`). Der Worker verarbeitet nicht vertrauenswürdige Inhalte (Repository-Code, Advisories,
Changelogs, Claude-Ausgaben) und hält den GitHub-App-Key und den Anthropic-Key. Eine Schwachstelle im
Worker wird damit zur Root-Kompromittierung des Servers. `web` und `postgres` erhalten den Socket nie.

Der Default ist deshalb **AI-Patching aus**: ohne Override läuft der Worker ohne Socket, deterministische
Fix-PRs, Triage und Bot-PR-Kommentare funktionieren trotzdem.

Bestehende Schutzmaßnahmen der Sandbox: kein Secret im Container, `--cap-drop=ALL`, `no-new-privileges`,
read-only Root, uid 1000, Ressourcenlimits, nur der Worktree gemountet, Egress nur über den Allowlist-Proxy,
Diff-Gate außerhalb der Sandbox.

Alternativen (vor dem Einschalten bewerten):

1. **Rootless Docker** auf dem Patchbot-Server: eigener `dockerd` unter einem dedizierten Benutzer, dessen
   Socket statt `/var/run/docker.sock` gemountet wird. Eine Kompromittierung bleibt auf diesen Benutzer
   begrenzt. Zu testen: uid-Mapping (Container-uid 1000 → subuid) gegenüber den Worktree-Dateien des Workers
   (uid 1000) und die Erreichbarkeit von `/var/lib/patchbot/repo-cache` für den rootless Daemon.
2. **Eigener Sandbox-Host:** kleine, separate VM nur für Sandbox-Container, Docker-API per mTLS. Eine
   Kompromittierung trifft dann nicht den Patchbot-Server mit seinen Secrets. Erfordert eine Code-Änderung
   in `research/sandbox.py` (Worktree per Kopie statt Bind-Mount übertragen).
3. Ein Docker-Socket-Proxy allein reicht nicht: `containers/create` muss erlaubt sein, und damit lassen sich
   Host-Pfade mounten.

Empfehlung: zunächst ohne AI-Patching starten; Patching erst mit rootless Docker einschalten, mittelfristig
einen eigenen Sandbox-Host vorsehen.

Hinweis zu den deterministischen Bumps: `npm install --package-lock-only --ignore-scripts` führt keine
Paket-Skripte aus. `uv lock` kann für Pakete ohne Wheel Build-Backends ausführen (Metadaten aus sdists) –
das läuft im Worker, nicht in der Sandbox.

## 15. Lokale Entwicklung

```bash
# Backend (SQLite, ohne Entra; Dev-Login nur mit DEBUG)
cd backend
uv sync
export DJANGO_DEBUG=true PATCHBOT_DEV_LOGIN=1
uv run python manage.py migrate
uv run python manage.py seed_dev              # Demo-Daten, verweigert ohne DEBUG
uv run python manage.py runserver 127.0.0.1:8020

# Frontend (Proxy /api → 127.0.0.1:8020, siehe frontend/proxy.conf.json)
cd frontend && npm ci && npx ng serve
```

Anmelden: `http://localhost:4200` öffnen. Ohne Entra-Konfiguration leitet der Login auf eine Dev-Login-Seite
mit allen aktiven Teammitgliedern weiter (nur mit `DJANGO_DEBUG=true` und `PATCHBOT_DEV_LOGIN=1`); Person anklicken.
`seed_dev` legt u. a. `dev@westcode.de` (Admin) an. Die Demo-Agents gelten 60 Minuten als frisch – danach
`seed_dev` erneut ausführen, sonst steht die Ampel auf Grau.

Tests: `cd backend && uv run pytest -q` (ohne `DJANGO_DEBUG`). Einzelne Worker-Runde: `uv run python manage.py
run_worker --once` (braucht GitHub-App-Konfiguration).

`PATCHBOT_DEV_LOGIN` mit `DJANGO_DEBUG=false` bricht den Start ab – das ist gewollt.

## 16. Offene Punkte

- **Hosting des Patchbot-Servers** (EC2 oder extern) entscheidet über die ECR-Anbindung (Abschnitt 7).
- **Reverse Proxy:** nginx oder Caddy; zwei Allowlists pflegen – Egress-IPs der 23 VMs (nur Agent-Endpunkt) und Büro/VPN (UI/API).
- **Trivy-DB-Aktualisierung:** `research.trivy.update_trivy_db()` wird vom Scheduler noch nicht aufgerufen;
  bis dahin übernimmt der Dienst `trivy-db` die Aktualisierung (alle 6 h).
- **Renovate:** bleibt als selbst gehosteter Runner im Stack. Falls Renovate org-weit anders betrieben wird
  (z. B. als GitHub App), kann der Dienst `renovate` samt `renovate.json`/`renovate.env` entfallen.
- **CI-Status über Commit-Statuses:** reporten Projekte nur Commit-Statuses statt Checks, braucht die App
  zusätzlich `Commit statuses: Read` und Patchbot eine Code-Anpassung.
- **Private Registries (CodeArtifact):** weder Worker-Bumps noch Sandbox haben Registry-Credentials; solche
  Bumps scheitern und werden als `COMPLEX` eingestuft.
- **Images bauen:** `backend/Dockerfile` und die Sandbox-Dockerfiles verwenden versionierte Basis-Images
  (Python 3.12, Node 22, Trivy 0.67.2, uv 0.9.5, Docker CLI 28); Updates laufen über Renovate.
