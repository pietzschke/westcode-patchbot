from datetime import date
from pathlib import Path
import re
from fleet.models import Host

DISTRO_EOL_DATES: dict[tuple[str, str], date] = {
    ("ubuntu", "18.04"): date(2023, 5, 31),
    ("ubuntu", "20.04"): date(2025, 5, 31),
    ("ubuntu", "22.04"): date(2027, 4, 30),
    ("ubuntu", "24.04"): date(2029, 5, 31),
    ("ubuntu", "26.04"): date(2031, 5, 31),
    ("debian", "10"): date(2024, 6, 30),
    ("debian", "11"): date(2026, 8, 31),
    ("debian", "12"): date(2028, 6, 30),
    ("debian", "13"): date(2030, 6, 30),
}

EXCLUDED_STACKS = {"hetzner-westcode-tiles"}

RESOURCE_HEADER_RE = re.compile(
    r'^\s*resource\s+"(?P<res_type>hcloud_server|ionoscloud_cube_server)"\s+"(?P<res_name>[^"]+)"\s*\{\s*$'
)
NAME_LINE_RE = re.compile(r'^\s*name\s*=\s*"(?P<name>[^"]+)"')
IMAGE_LINE_RE = re.compile(
    r'^\s*(?:image|image_name)\s*=\s*(?:"(?P<image>[^"]+)"|(?P<null>null))'
)


def distro_eol_date(distro: str, version: str) -> date | None:
    return DISTRO_EOL_DATES.get((distro.strip().lower(), version.strip().lower()))


def is_distro_eol(distro: str, version: str, today: date | None = None) -> bool:
    check_date = today or date.today()
    key = (distro.strip().lower(), version.strip().lower())
    eol_date = DISTRO_EOL_DATES.get(key)
    if eol_date is None:
        return False
    return check_date > eol_date


def _parse_server_resources(tf_text: str) -> list[dict[str, str | None]]:
    servers: list[dict[str, str | None]] = []
    in_resource = False
    depth = 0
    current: dict[str, str | None] = {}

    for raw_line in tf_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if not in_resource:
            header_match = RESOURCE_HEADER_RE.match(raw_line)
            if header_match:
                in_resource = True
                depth = 1
                current = {
                    "res_type": header_match.group("res_type"),
                    "res_name": header_match.group("res_name"),
                    "hostname": None,
                    "declared_image": None,
                }
            continue

        if depth == 1:
            name_match = NAME_LINE_RE.match(raw_line)
            if name_match:
                current["hostname"] = name_match.group("name").strip()
            image_match = IMAGE_LINE_RE.match(raw_line)
            if image_match:
                if image_match.group("image"):
                    current["declared_image"] = image_match.group("image").strip()
                else:
                    current["declared_image"] = None

        # Update brace depth ignoring strings and inline comments
        code_part = re.sub(r'"[^"]*"', '""', raw_line).split("#", 1)[0]
        depth += code_part.count("{") - code_part.count("}")
        if depth <= 0:
            if current.get("hostname"):
                servers.append(current)
            in_resource = False
            depth = 0
            current = {}

    return servers


def _parse_distro_version(declared_image: str | None) -> tuple[str, str]:
    if not declared_image:
        return ("", "")
    normalized = declared_image.strip().lower().replace(":", "-")
    if "-" not in normalized:
        return (normalized, "")
    distro, version = normalized.split("-", 1)
    return (distro, version)


def _slugify_hostname(hostname: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", hostname.lower()).strip("-")


def sync_infra_hosts(infra_root: Path, today: date | None = None) -> list[Host]:
    stacks_dir = Path(infra_root) / "stacks"
    tf_files: list[tuple[str, str, Path]] = []

    for server_tf in sorted(stacks_dir.glob("hetzner-*/servers.tf")):
        stack_name = server_tf.parent.name
        if stack_name in EXCLUDED_STACKS:
            continue
        tf_files.append(("hetzner", stack_name, server_tf))

    ionos_tf = stacks_dir / "ionos-westcode" / "server.tf"
    if ionos_tf.exists():
        tf_files.append(("ionos", "ionos-westcode", ionos_tf))

    check_date = today or date.today()

    for provider, stack_name, tf_path in tf_files:
        text = tf_path.read_text(encoding="utf-8")
        for srv in _parse_server_resources(text):
            hostname = srv["hostname"]
            if not hostname:
                continue
            declared_image = srv["declared_image"]
            defaults: dict[str, object] = {
                "slug": _slugify_hostname(hostname),
                "provider": provider,
                "stack_name": stack_name,
                "declared_image": declared_image,
            }
            # The declared image is only a placeholder until the agent reports the live OS. After that the
            # agent is authoritative (in-place release upgrades do not change servers.tf).
            has_reported = Host.objects.filter(hostname=hostname, last_seen_at__isnull=False).exists()
            if declared_image is not None and not has_reported:
                os_distro, os_version = _parse_distro_version(declared_image)
                known = bool(os_distro and os_version)
                defaults["os_distro"] = os_distro
                defaults["os_version"] = os_version
                defaults["is_os_eol"] = is_distro_eol(os_distro, os_version, today=check_date) if known else False
                defaults["os_eol_date"] = distro_eol_date(os_distro, os_version) if known else None

            Host.objects.update_or_create(
                hostname=hostname,
                defaults=defaults,
            )

    return list(Host.objects.all())
