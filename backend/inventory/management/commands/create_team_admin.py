from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from inventory.entra import ALLOWED_EMAIL_DOMAIN
from inventory.models import TeamMember


class Command(BaseCommand):
    help = (
        "Creates (or promotes) an active admin team member so the first Entra login on a fresh install "
        "can bind to it. Idempotent: re-running only (re)sets name, is_admin and is_active."
    )

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="@westcode.de address used for the Entra login.")
        parser.add_argument("--name", required=True, help="Display name.")
        parser.add_argument(
            "--default-infra-owner",
            action="store_true",
            help="Also make this member the (single) default infra owner.",
        )

    def handle(self, *args, **options):
        email = (options["email"] or "").strip().lower()
        name = (options["name"] or "").strip()
        if not email.endswith(ALLOWED_EMAIL_DOMAIN) or email.count("@") != 1:
            raise CommandError(f"Only {ALLOWED_EMAIL_DOMAIN} addresses are allowed: {email!r}")
        if not name:
            raise CommandError("--name must not be empty.")

        try:
            with transaction.atomic():
                member = TeamMember.objects.select_for_update().filter(email=email).first()
                created = member is None
                if created:
                    member = TeamMember(email=email)
                member.name = name
                member.is_admin = True
                member.is_active = True
                if options["default_infra_owner"]:
                    member.is_default_infra_owner = True
                member.full_clean(exclude=["user"])
                member.save()
        except ValidationError as exc:
            if "is_default_infra_owner" in exc.message_dict:
                raise CommandError("Another active team member already is the default infra owner.") from exc
            raise CommandError(f"Invalid team member: {exc.message_dict}") from exc

        verb = "Created" if created else "Updated"
        self.stdout.write(self.style.SUCCESS(f"{verb} admin team member {member}."))
