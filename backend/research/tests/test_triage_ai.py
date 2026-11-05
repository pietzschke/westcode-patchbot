import json

import anthropic
import httpx2
import pytest

from research.models import TriageAnalysisCache
from research.triage_ai import apply_triage
from testing.factories import make_finding
from testing.fakes import FakeLLM

VALID = {
    "reachability": "REACHABLE", "reachability_reason_category": "OTHER", "complexity": "SIMPLE",
    "confidence": 0.85, "summary_de": "lodash.template wird in src/report.ts genutzt.",
    "breaking_changes_de": "", "affected_files": ["src/report.ts:42"],
}


@pytest.mark.django_db
def test_request_uses_structured_output_fallbacks_and_untrusted_blocks(settings, tmp_path):
    settings.PATCHBOT_CLAUDE_MODEL = "claude-sonnet-5-5"
    llm = FakeLLM(output=VALID)
    f = make_finding(layer="APPLICATION", package_name="lodash")
    apply_triage(f, client=llm, checkout=tmp_path)
    call = llm.calls[0]
    assert call["model"] == "claude-sonnet-5-5"
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert "tool_choice" not in call and "tools" not in call
    assert call["fallbacks"] == "default"
    assert call["betas"] == ["server-side-fallback-2026-07-01"]
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "<untrusted_advisory>" in call["messages"][0]["content"]
    assert (f.triage_status, f.complexity, f.state) == ("TRIAGED", "SIMPLE", "NEW")
    assert f.affected_files == ["src/report.ts:42"]


@pytest.mark.django_db
def test_no_client_means_untriaged_and_relevant(tmp_path):
    f = make_finding(layer="APPLICATION")
    apply_triage(f, client=None, checkout=tmp_path)
    assert (f.triage_status, f.complexity, f.state) == ("UNTRIAGED", "COMPLEX", "NEW")


@pytest.mark.django_db
def test_invalid_model_output_means_untriaged(tmp_path):
    f = make_finding(layer="APPLICATION")
    apply_triage(f, client=FakeLLM(output={**VALID, "reachability": "MAYBE"}), checkout=tmp_path)
    assert f.triage_status == "UNTRIAGED"


@pytest.mark.django_db
def test_out_of_range_confidence_means_untriaged(tmp_path):
    f = make_finding(layer="APPLICATION")
    apply_triage(f, client=FakeLLM(output={**VALID, "confidence": 1.7}), checkout=tmp_path)
    assert f.triage_status == "UNTRIAGED"


@pytest.mark.django_db
def test_refusal_means_untriaged_and_is_logged(tmp_path):
    f = make_finding(layer="APPLICATION")
    apply_triage(f, client=FakeLLM(output=VALID, stop_reason="refusal", refusal_category="cyber"), checkout=tmp_path)
    assert (f.triage_status, f.state) == ("UNTRIAGED", "NEW")
    assert f.events.filter(note__icontains="abgelehnt").exists()


@pytest.mark.django_db
def test_api_error_means_untriaged(tmp_path):
    error = anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))
    f = make_finding(layer="APPLICATION")
    apply_triage(f, client=FakeLLM(raises=error), checkout=tmp_path)
    assert f.triage_status == "UNTRIAGED"


@pytest.mark.django_db
def test_analysis_is_cached(tmp_path):
    llm = FakeLLM(output=VALID)
    f = make_finding(layer="APPLICATION", package_name="lodash", target_version="4.17.21")
    apply_triage(f, client=llm, checkout=tmp_path)
    apply_triage(f, client=llm, checkout=tmp_path)
    assert len(llm.calls) == 1
    assert json.loads(TriageAnalysisCache.objects.get().result_json)["reachability"] == "REACHABLE"


@pytest.mark.django_db
def test_filtered_only_through_policy_gate(tmp_path):
    (tmp_path / "package-lock.json").write_text('{"packages": {"node_modules/jest": {"version": "29.0.0", "dev": true}}}')
    llm = FakeLLM(output={**VALID, "reachability": "NOT_REACHABLE",
                          "reachability_reason_category": "DEV_ONLY", "confidence": 0.95})
    f = make_finding(layer="APPLICATION", ecosystem="npm", package_name="jest", highest_severity="HIGH")
    apply_triage(f, client=llm, checkout=tmp_path)
    assert f.state == "FILTERED_IRRELEVANT"
    assert f.events.filter(to_state="FILTERED_IRRELEVANT").exists()


@pytest.mark.django_db
def test_critical_is_never_filtered_even_if_claude_says_unreachable(tmp_path):
    (tmp_path / "package-lock.json").write_text('{"packages": {"node_modules/jest": {"version": "29.0.0", "dev": true}}}')
    llm = FakeLLM(output={**VALID, "reachability": "NOT_REACHABLE",
                          "reachability_reason_category": "DEV_ONLY", "confidence": 0.99})
    f = make_finding(layer="APPLICATION", ecosystem="npm", package_name="jest", highest_severity="CRITICAL")
    apply_triage(f, client=llm, checkout=tmp_path)
    assert f.state == "NEW"
    assert f.reachability == "NOT_REACHABLE"


@pytest.mark.django_db
def test_filtered_finding_reopens_when_gate_no_longer_holds(tmp_path):
    llm = FakeLLM(output={**VALID, "reachability": "NOT_REACHABLE",
                          "reachability_reason_category": "NO_CALL_SITE", "confidence": 0.95})
    f = make_finding(layer="APPLICATION", package_name="left-pad", highest_severity="MEDIUM",
                     state="FILTERED_IRRELEVANT", kev_listed=True)
    apply_triage(f, client=llm, checkout=tmp_path)
    assert f.state == "NEW"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "layer,package,expected",
    [("INFRASTRUCTURE", "openssl", "SIMPLE"), ("INFRASTRUCTURE", "__reboot__", "SIMPLE"),
     ("INFRASTRUCTURE", "__os_eol__", "COMPLEX"), ("CONTAINER_IMAGE", "openssl", "SIMPLE")],
)
def test_non_application_layers_skip_llm(layer, package, expected):
    llm = FakeLLM(output=VALID)
    f = make_finding(layer=layer, package_name=package)
    apply_triage(f, client=llm, checkout=None)
    assert (f.complexity, f.triage_status) == (expected, "TRIAGED")
    assert llm.calls == []
