from types import SimpleNamespace

import pytest

from research.triage_ai import TriageResult, policy_gate


def finding(severity="HIGH", kev=False, epss=0.01):
    return SimpleNamespace(highest_severity=severity, kev_listed=kev, max_epss=epss)


def result(reach="NOT_REACHABLE", conf=0.9, cat="DEV_ONLY"):
    return TriageResult(reachability=reach, reachability_reason_category=cat, complexity="SIMPLE",
                        confidence=conf, summary_de="", breaking_changes_de="", affected_files=[])


@pytest.mark.parametrize(
    "f,r,evidence,expected",
    [
        (finding(), result(), {"dev_only": True, "call_site_hits": 3}, True),
        (finding(severity="CRITICAL"), result(), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(kev=True), result(), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(epss=0.2), result(), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(), result(conf=0.7), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(), result(reach="UNLIKELY_REACHABLE"), {"dev_only": True, "call_site_hits": 0}, False),
        (finding(), result(), {"dev_only": False, "call_site_hits": 0}, False),
        (finding(severity="MEDIUM"), result(cat="TEST_ONLY"), {"dev_only": True, "call_site_hits": 4}, True),
        (finding(severity="MEDIUM"), result(cat="NO_CALL_SITE"), {"dev_only": False, "call_site_hits": 0}, True),
        (finding(severity="MEDIUM"), result(cat="NO_CALL_SITE"), {"dev_only": False, "call_site_hits": 2}, False),
        (finding(severity="MEDIUM"), result(cat="NO_CALL_SITE"), {"dev_only": False, "call_site_hits": None}, False),
        (finding(severity="MEDIUM"), result(cat="UNUSED_FEATURE"), {"dev_only": False, "call_site_hits": 0}, False),
    ],
)
def test_policy_gate(f, r, evidence, expected):
    assert policy_gate(f, r, evidence) is expected
