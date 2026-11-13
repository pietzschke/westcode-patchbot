import pytest
from django.core.management import CommandError, call_command

from controlplane.ampel import compute_ampel
from triage.models import STATES, Finding


@pytest.mark.django_db
def test_seed_dev_refuses_without_debug(settings):
    settings.DEBUG = False
    with pytest.raises(CommandError):
        call_command("seed_dev")


@pytest.mark.django_db
def test_seed_dev_is_idempotent_and_covers_every_state(settings):
    settings.DEBUG = True
    call_command("seed_dev")
    count = Finding.objects.count()
    call_command("seed_dev")
    assert Finding.objects.count() == count
    assert set(Finding.objects.values_list("state", flat=True)) == {s for s, _ in STATES}
    ampel = compute_ampel()
    assert ampel["causes"] == [] and ampel["color"] == "RED"
