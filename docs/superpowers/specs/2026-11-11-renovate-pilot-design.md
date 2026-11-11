# Kurzdesign: Zentraler Renovate-Pilot per GitHub Action (`ack-desk`)

**Datum:** 2026-11-11 · **Repository:** `westcoder/westcode-patchbot` · **Umfang:** Kleine Änderung

---

## 1. Kontext & Warum (Intent)

Bevor der vollständige Patchbot-v2-Stack (Server, Entra ID, Slack-App, 23 Host-Agents) in Betrieb geht, soll bereits ein verlässlicher, ressourcenschonender Dependency-Update-Prozess starten. Da einzelnes Aktualisieren jeder Bibliothek zu viele CircleCI-Läufe und Credits kostet (allein `e2e` in `ack-desk` verbraucht ~285 Credits pro Lauf), soll Renovate einmal nachts laufen, Updates bündeln und nach grünen Checks automatisch mergen. Gestartet wird bewusst ohne AWS CodeArtifact am Pilotprojekt `westcoder/ack-desk`.

## 2. Ziele, Nicht-Ziele & Anti-Ziele

- **Ziele:**
  - Zentral gesteuerter nächtlicher Renovate-Lauf aus `westcoder/westcode-patchbot` heraus ohne Änderungen an `ack-desk`.
  - Pro Repo ein einziger Sammel-PR für alle `minor`-, `patch`-, `pin`- und `digest`-Updates mit Automerge bei grüner CI.
  - Eigene Einzel-PRs ohne Automerge für `major`-Updates (`rebaseWhen: "conflicted"`) sowie für Security-Updates.
  - Kompatibilität mit Patchbot v2 (`westcode-renovate[bot]` wird als Bot-PR-Quelle erkannt) und direkter Ausbaupfad für AWS CodeArtifact (Account `069962555850`).
- **Nicht-Ziele:** Anbindung der 19 CodeArtifact-Projekte in Phase 1; Deployment des Patchbot-v2-Backends.
- **Anti-Ziele:** Kein Automerge ohne echten grünen CI-Check (`ignoreTests: false`); kein nächtliches Dauer-Rebasing offener PRs; keine Automerges am Freitag oder Wochenende.

## 3. Rahmenbedingungen (Constraints)

- **`ack-desk`-Besonderheiten:** Ist ein GitHub-Fork von `westcoder/angular-django-scaffold` (erfordert `includeForks: true`), entwickelt auf `develop` (`deploy-staging` auf `develop`, kein Prod-Deploy), führt täglich um `01:00 UTC` `nightly-merge-back.yml` (`main → develop`) aus und erzwingt Conventional Commits im PR-Titel (`semanticCommits: "enabled"`).
- **GitHub Actions Cron:** Geplante Workflows (`schedule`) werden von GitHub nur ausgeführt, wenn sie auf dem Default-Branch (`main`) von `westcoder/westcode-patchbot` liegen.

## 4. Betrachtete Ansätze & Entscheidung

1. **Geplante GitHub Action in `westcoder/westcode-patchbot` + eigene GitHub App `westcode-renovate` *(Gewählt)*:**
   Kein eigener Server nötig, garantierter Einmal-Takt pro Nacht, zentrale Steuerung ohne Onboarding-PRs im Ziel-Repo. Später durch 5 Zeilen AWS-OIDC (`codeartifact-read-boundary`) nahtlos für die 19 CodeArtifact-Projekte erweiterbar.
2. **Gehostete Mend Renovate GitHub App (SaaS) *(Verworfen)*:**
   Scheitert später in Phase 2 an den 12h-Tokens von AWS CodeArtifact (würde dann doch einen Wechsel oder Doppelbetrieb erzwingen) und verlangt Onboarding-PRs sowie Fork-Sonderkonfiguration im Ziel-Repo.
3. **Vorab-Betrieb des `renovate`-Containers aus `deploy/compose.yaml` auf einer VM *(Verworfen)*:**
   Erzeugt sofortigen VM- und Secret-Betriebsaufwand vor dem eigentlichen Patchbot-Rollout ohne Mehrwert gegenüber GitHub Actions + OIDC.

## 5. Festgelegter Aufbau

- **GitHub App (`westcode-renovate` in Org `westcoder`):** Installiert zunächst nur auf `westcoder/ack-desk`. Minimale Rechte: `Contents: Read & write`, `Pull requests: Read & write`, `Issues: Read & write`, `Checks: Read-only`, `Commit statuses: Read-only`. Hinterlegt als Repo-Secrets `RENOVATE_APP_ID` und `RENOVATE_APP_PRIVATE_KEY` in `westcoder/westcode-patchbot`.
- **Workflow (`.github/workflows/renovate.yml`):**
  - `Mo–Do` um `02:00 UTC` (nach `nightly-merge-back` um `01:00 UTC`): erstellt/aktualisiert den Sammel-PR gegen `develop` → löst genau einen CircleCI-Durchlauf aus.
  - `Mo–Do` um `03:00 UTC`: prüft die abgeschlossenen CircleCI-/GitHub-Checks (~30 Sek.) und merged den grünen Sammel-PR automatisch (`platformAutomerge: false`, damit keine Änderung an der Branch-Protection von `ack-desk` nötig ist).
  - Zusätzlich manuell per `workflow_dispatch` startbar.
- **Zentrale Konfiguration (`deploy/renovate.json`):** `onboarding: false`, `requireConfig: "optional"`, `includeForks: true`, `semanticCommits: "enabled"`, Manager `poetry`, `pep621`, `npm`, `dockerfile`, `docker-compose`, `github-actions`, `circleci`, Ziel `[{"repository": "westcoder/ack-desk", "baseBranches": ["develop"]}]`. Die bisher falsche CodeArtifact-Account-ID (`533267181938`) wird für Phase 2 auf `069962555850` dokumentiert/vorbereitet.
- **Patchbot-Integration & Aufräumen:** `BOT_LOGINS` in `backend/research/bot_prs.py` wird um `"westcode-renovate[bot]"` ergänzt; der nun durch GitHub Actions abgelöste `renovate`-Dienst entfällt aus `deploy/compose.yaml` (inkl. Runbook-Aktualisierung in `docs/runbooks/patchbot-v2-rollout.md`).

## 6. Entscheidungen des Builders (Builder's Calls)

- **Gefahrloser Ersttest (`dry_run`-Schalter):** `workflow_dispatch` bekommt ein optionales Input `dry_run` (`full` / `false`), sodass der erste Testlauf in GitHub Actions im Log zeigt, welchen PR Renovate für `ack-desk` bauen würde, bevor tatsächlich ein PR geöffnet wird.
- **Gepinnte Action-/Image-Versionen & Bot-Identität:** Nutzung von `actions/create-github-app-token@v2` und `renovatebot/github-action` mit sauber gesetzter Bot-`gitAuthor`-Adresse der GitHub App.
