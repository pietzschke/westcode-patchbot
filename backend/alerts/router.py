from collections.abc import Iterable
import json
import os
from typing import Any, Protocol
import urllib.request

from django.core.mail import send_mail
from django.db import transaction

from alerts.models import AlertFingerprint
from catalog.models import HostTarget, ServiceGroup
from fleet.models import Host, HostContainer
from rollouts.models import RolloutPlan


class DigestEntry(dict):
    """Dictionary that also supports attribute-style access for convenience."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class AlertTransport(Protocol):
    def send_slack(self, text: str) -> Any: ...

    def create_zammad_ticket(self, title: str, body: str, group: str = "Infra") -> str: ...


class HttpAlertTransport:
    def __init__(
        self,
        slack_webhook_url: str | None = None,
        zammad_base_url: str | None = None,
        zammad_token: str | None = None,
        zammad_customer: str = "patchbot@westcode.de",
        from_email: str = "patchbot@westcode.de",
        timeout: float = 10.0,
    ) -> None:
        self.slack_webhook_url = (
            slack_webhook_url
            if slack_webhook_url is not None
            else os.environ.get("PATCHBOT_SLACK_WEBHOOK_URL", "")
        ).strip()
        self.zammad_base_url = (
            zammad_base_url
            if zammad_base_url is not None
            else os.environ.get("PATCHBOT_ZAMMAD_URL", "https://support.westcode.de")
        ).rstrip("/")
        self.zammad_token = (
            zammad_token
            if zammad_token is not None
            else os.environ.get("PATCHBOT_ZAMMAD_TOKEN", "")
        ).strip()
        self.zammad_customer = zammad_customer
        self.from_email = from_email
        self.timeout = timeout

    def send_slack(self, text: str) -> None:
        if not self.slack_webhook_url:
            return
        payload = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(
            self.slack_webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            resp.read()

    def create_zammad_ticket(
        self,
        title: str,
        body: str,
        group: str = "Infra",
    ) -> str:
        if not self.zammad_base_url or not self.zammad_token:
            return ""
        url = f"{self.zammad_base_url}/api/v1/tickets"
        payload = json.dumps(
            {
                "title": title,
                "group": group,
                "customer": self.zammad_customer,
                "article": {
                    "subject": title,
                    "body": body,
                    "type": "note",
                    "internal": False,
                },
            }
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
        }
        if self.zammad_token:
            headers["Authorization"] = f"Bearer {self.zammad_token}"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8")
        if not raw:
            return ""
        data = json.loads(raw)
        return str(data.get("number") or data.get("id") or "")

    def send_email(self, recipient: str, subject: str, body: str) -> int:
        return send_mail(
            subject=subject,
            message=body,
            from_email=self.from_email,
            recipient_list=[recipient],
            fail_silently=False,
        )


def notify_critical_cve(
    service_group: ServiceGroup,
    transport: AlertTransport,
) -> bool:
    cve_id = (service_group.highest_cve_id or "").strip()
    if not cve_id:
        return False

    fingerprint = f"cve:{service_group.slug}:{cve_id}"
    with transaction.atomic():
        if AlertFingerprint.objects.filter(fingerprint=fingerprint).exists():
            return False

        version_jump = (
            f"{service_group.current_version_summary} -> {service_group.target_version}"
            if service_group.current_version_summary and service_group.target_version
            else (service_group.target_version or service_group.current_version_summary or "n/a")
        )
        severity = service_group.highest_severity or "HIGH"
        title = (
            f"[Patchbot] {cve_id} ({severity}) in {service_group.display_name} "
            f"– Fix {service_group.target_version or 'verfügbar'}"
        )
        body = (
            f"Für den Dienst {service_group.display_name} ({service_group.slug}) liegt ein "
            f"Sicherheits-Update mit verfügbarem Fix vor.\n\n"
            f"- CVE: {cve_id} ({severity})\n"
            f"- Version: {version_jump}\n"
            f"- Zusammenfassung: {service_group.summary_line}\n"
        )
        slack_text = (
            f":warning: *Westcode Patchbot – Jetzt handeln:* `{cve_id}` ({severity}) "
            f"auf *{service_group.display_name}* ({version_jump}) – {service_group.summary_line}"
        )

        transport.send_slack(slack_text)
        ticket_ref = transport.create_zammad_ticket(title=title, body=body, group="Infra")

        AlertFingerprint.objects.create(
            fingerprint=fingerprint,
            channel="slack+zammad",
            external_ref=str(ticket_ref or ""),
        )
        return True


def notify_rollout_rollback(
    plan: RolloutPlan,
    logs: str = "",
    transport: AlertTransport | None = None,
) -> bool:
    active_transport = transport if transport is not None else HttpAlertTransport()
    fingerprint = f"rollback:{plan.id}"
    with transaction.atomic():
        if AlertFingerprint.objects.filter(fingerprint=fingerprint).exists():
            return False

        sg = plan.service_group
        title = f"[Patchbot] Rollout-Rollback für {sg.display_name} (Plan {plan.id})"
        body = (
            f"Der serielle Canary-Rollout für {sg.display_name} ({sg.slug}) "
            f"wurde nach einem fehlgeschlagenen Healthcheck automatisch zurückgerollt.\n\n"
            f"- Plan-ID: {plan.id}\n"
            f"- Status: {plan.status}\n"
            f"- Zielversion: {sg.target_version}\n\n"
            f"Letzte Container-/Agent-Logs:\n{logs}\n"
        )
        slack_text = (
            f":rotating_light: *Westcode Patchbot – Auto-Rollback:* "
            f"Rollout für *{sg.display_name}* (Plan `{plan.id}`) fehlgeschlagen und zurückgerollt.\n"
            f"```{logs[:500]}```"
        )

        active_transport.send_slack(slack_text)
        ticket_ref = active_transport.create_zammad_ticket(title=title, body=body, group="Infra")

        AlertFingerprint.objects.create(
            fingerprint=fingerprint,
            channel="slack+zammad",
            external_ref=str(ticket_ref or ""),
        )
        return True


def _serialize_group_for_digest(sg: ServiceGroup) -> DigestEntry:
    return DigestEntry(
        id=sg.id,
        slug=sg.slug,
        display_name=sg.display_name,
        logo_key=sg.logo_key,
        category=sg.category,
        current_version_summary=sg.current_version_summary,
        target_version=sg.target_version,
        highest_cve_id=sg.highest_cve_id,
        highest_severity=sg.highest_severity,
        summary_line=sg.summary_line,
    )


def _serialize_host_for_digest(host: Host, dirty_dirs: list[str] | None = None) -> DigestEntry:
    is_eol = bool(getattr(host, "is_os_eol", False) or getattr(host, "is_eol", False))
    return DigestEntry(
        id=host.id,
        slug=host.slug,
        hostname=host.hostname,
        provider=host.provider,
        stack_name=host.stack_name,
        os_distro=host.os_distro,
        os_version=host.os_version,
        is_os_eol=is_eol,
        is_eol=is_eol,
        reboot_required=host.reboot_required,
        working_dirs=dirty_dirs or [],
    )


def build_weekly_digest(
    groups: Iterable[ServiceGroup],
    hosts: Iterable[Host],
) -> dict[str, Any]:
    group_list = list(groups)
    host_list = list(hosts)

    action_required = [
        _serialize_group_for_digest(sg)
        for sg in group_list
        if sg.category == "action_required"
    ]
    ready = [
        _serialize_group_for_digest(sg)
        for sg in group_list
        if sg.category != "action_required"
    ]

    eol_hosts = [
        _serialize_host_for_digest(h)
        for h in host_list
        if getattr(h, "is_os_eol", False) or getattr(h, "is_eol", False)
    ]

    dirty_dirs_by_host_id: dict[int, set[str]] = {}
    host_ids = [h.id for h in host_list if h.id is not None]
    if host_ids:
        for ht in HostTarget.objects.filter(host_id__in=host_ids, git_clean=False):
            dirty_dirs_by_host_id.setdefault(ht.host_id, set()).add(ht.working_dir or "/opt")
        for hc in HostContainer.objects.filter(host_id__in=host_ids, git_clean=False):
            dirty_dirs_by_host_id.setdefault(hc.host_id, set()).add(hc.working_dir or "/opt")

    dirty_git_hosts: list[DigestEntry] = []
    for h in host_list:
        explicit_dirty = getattr(h, "git_clean", None) is False
        dirs = sorted(dirty_dirs_by_host_id.get(h.id, set()))
        if explicit_dirty or dirs:
            dirty_git_hosts.append(_serialize_host_for_digest(h, dirty_dirs=dirs))

    subject = (
        f"[Westcode Patchbot] Wochen-Digest: "
        f"{len(action_required)} Jetzt handeln, {len(ready)} Bereit zum Ausrollen"
    )

    lines: list[str] = [
        "# Westcode Patchbot – Wochen-Digest",
        "",
        f"## Jetzt handeln ({len(action_required)})",
    ]
    if action_required:
        for sg in action_required:
            cve_part = f" [{sg['highest_cve_id']}]" if sg["highest_cve_id"] else ""
            lines.append(
                f"- {sg['display_name']}{cve_part}: "
                f"{sg['current_version_summary']} -> {sg['target_version']} "
                f"({sg['summary_line']})"
            )
    else:
        lines.append("- Keine kritischen Sicherheits-Updates offen.")

    lines.extend(["", f"## Bereit zum Ausrollen ({len(ready)})"])
    if ready:
        for sg in ready:
            lines.append(
                f"- {sg['display_name']}: "
                f"{sg['current_version_summary']} -> {sg['target_version']} "
                f"({sg['summary_line']})"
            )
    else:
        lines.append("- Keine ausstehenden Versions-Updates.")

    lines.extend(["", f"## EOL-Betriebssysteme ({len(eol_hosts)})"])
    if eol_hosts:
        for h in eol_hosts:
            os_label = f"{h['os_distro']} {h['os_version']}".strip() or "EOL"
            lines.append(f"- {h['hostname']} ({os_label})")
    else:
        lines.append("- Keine EOL-Systeme.")

    lines.extend(["", f"## Uncommittete Git-Änderungen unter /opt ({len(dirty_git_hosts)})"])
    if dirty_git_hosts:
        for h in dirty_git_hosts:
            dirs_label = ", ".join(h["working_dirs"]) if h["working_dirs"] else "/opt"
            lines.append(f"- {h['hostname']} ({dirs_label})")
    else:
        lines.append("- Alle geprüften /opt-Repositories sind sauber.")

    body = "\n".join(lines)

    return {
        "subject": subject,
        "body": body,
        "action_required": action_required,
        "ready": ready,
        "eol_hosts": eol_hosts,
        "dirty_git_hosts": dirty_git_hosts,
    }
