import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server import (
    crosswalk_to_ai_act, classify_ai_risk_tier, list_provider_obligations,
    list_deployer_obligations, generate_fria_inputs, generate_ifu_skeleton,
    crosswalk_to_nist_rmf, crosswalk_to_iso_42001, chain_attestations,
    check_uk_ai_bill_art_22c, MEOK_COMPLIANCE_TO_AI_ACT_MAP, AI_ACT_RISK_TIERS,
    PROVIDER_OBLIGATIONS_HIGH_RISK, DEPLOYER_OBLIGATIONS_HIGH_RISK,
)


def _call(t, **kw):
    fn = t.fn if hasattr(t, "fn") else t
    return fn(**kw)


def test_crosswalk_tacho_is_high_risk():
    r = _call(crosswalk_to_ai_act, source_mcp="meok-tacho-audit-mcp",
              deployment_geography="EU")
    assert r["risk_tier"] == "high"
    assert "Art 9" in r["applicable_articles"]
    assert "2_critical_infrastructure" in r["annex_iii_categories"]


def test_crosswalk_fmcsa_is_limited():
    r = _call(crosswalk_to_ai_act, source_mcp="meok-fmcsa-hours-of-service-mcp",
              deployment_geography="US")
    assert r["risk_tier"] == "limited"


def test_crosswalk_unknown_mcp_returns_advisory():
    r = _call(crosswalk_to_ai_act, source_mcp="meok-unknown-mcp")
    assert r["known"] is False
    assert "LIMITED" in r["advisory"]


def test_crosswalk_public_body_triggers_fria():
    r = _call(crosswalk_to_ai_act, source_mcp="meok-tacho-audit-mcp",
              deployer_is_public_body=True)
    assert r["fria_required_for_deployer"] is True


def test_classify_credit_use_is_high_risk():
    r = _call(classify_ai_risk_tier, use_case_description="Score haulier credit-worthiness",
              affects_essential_services=True)
    assert r["risk_tier"] == "high"


def test_classify_chatbot_is_limited():
    r = _call(classify_ai_risk_tier,
              use_case_description="Customer support chatbot for booking grab hire")
    assert r["risk_tier"] == "limited"


def test_classify_social_scoring_is_unacceptable():
    r = _call(classify_ai_risk_tier,
              use_case_description="Driver social scoring across all UK firms")
    assert r["risk_tier"] == "unacceptable"


def test_classify_minimal_default():
    r = _call(classify_ai_risk_tier,
              use_case_description="Internal email spam filter")
    assert r["risk_tier"] == "minimal"


def test_provider_obligations_high_risk_has_many():
    r = _call(list_provider_obligations, risk_tier="high")
    assert r["count"] >= 15  # >= 15 of 19 listed


def test_provider_obligations_limited_just_transparency():
    r = _call(list_provider_obligations, risk_tier="limited")
    assert any("Transparency" in o for o in r["obligations"])


def test_deployer_obligations_excludes_fria_for_private_body():
    r = _call(list_deployer_obligations, risk_tier="high", deployer_is_public_body=False)
    assert not any("FRIA" in o for o in r["obligations"])


def test_deployer_obligations_includes_fria_for_public_body():
    r = _call(list_deployer_obligations, risk_tier="high", deployer_is_public_body=True)
    assert any("FRIA" in o for o in r["obligations"])


def test_fria_skeleton_has_6_sections():
    r = _call(generate_fria_inputs, deployer_name="Acme Council",
              deployer_country="UK",
              affected_persons_groups=["drivers", "passengers"],
              ai_use_purpose="Tachograph audit AI")
    assert len(r["fria_sections"]) == 6
    assert r["affected_groups"] == ["drivers", "passengers"]


def test_ifu_skeleton_has_7_sections():
    r = _call(generate_ifu_skeleton, provider_legal_name="MEOK AI Labs Ltd",
              ai_system_name="meok-tacho-audit-mcp",
              intended_purpose="Driver hours infringement detection",
              capabilities="EU 561/2006 audit",
              limitations="Not a replacement for human TM")
    assert len(r["ifu_sections"]) == 7


def test_nist_rmf_has_4_functions():
    r = _call(crosswalk_to_nist_rmf, ai_act_risk_tier="high")
    assert r["nist_functions"] == ["GOVERN", "MAP", "MEASURE", "MANAGE"]
    assert "Art 9" in r["mapping"]["GOVERN"]


def test_iso_42001_includes_critical_clauses():
    r = _call(crosswalk_to_iso_42001, ai_act_risk_tier="high")
    assert "6" in r["high_risk_critical_clauses"]
    assert "A.9" in r["high_risk_critical_clauses"]


def test_chain_attestations_creates_chain_id():
    compliance = {"issuer": "meok-tacho-audit-mcp", "sig": "abc123", "ts": "2026-06-06T10:00:00Z",
                  "tool": "calculate_ocrs_band"}
    governance = {"issuer": "meok-eu-ai-act-art-13-ifu-mcp", "sig": "def456",
                  "ts": "2026-06-06T10:00:01Z", "tool": "generate_ifu"}
    r = _call(chain_attestations, compliance_attestation=compliance,
              governance_attestation=governance)
    assert "chain_id" in r
    assert r["compliance"]["issuer"] == "meok-tacho-audit-mcp"
    assert r["governance"]["issuer"] == "meok-eu-ai-act-art-13-ifu-mcp"


def test_chain_attestations_without_governance_still_works():
    compliance = {"issuer": "meok-bs7121-mcp", "sig": "x", "ts": "t", "tool": "classify_lift_category"}
    r = _call(chain_attestations, compliance_attestation=compliance)
    assert r["governance"]["issuer"] == ""


def test_uk_ai_bill_22c_triggers_for_fully_automated():
    r = _call(check_uk_ai_bill_art_22c,
              use_case_description="Automated insurance-risk decision",
              has_human_in_loop=False, has_explanation_capability=False,
              has_appeal_mechanism=False)
    assert r["triggers_art_22c"] is True
    assert len(r["compliance_gaps"]) == 3


def test_uk_ai_bill_22c_compliant_with_human_in_loop():
    r = _call(check_uk_ai_bill_art_22c,
              use_case_description="Augmented insurance decision",
              has_human_in_loop=True, has_explanation_capability=True,
              has_appeal_mechanism=True)
    assert r["triggers_art_22c"] is False
    assert r["compliance_gaps"] == []


def test_map_table_covers_all_15_trade_mcps():
    expected = {
        "meok-tacho-audit-mcp", "meok-fmcsa-hours-of-service-mcp",
        "meok-bs7121-mcp", "meok-ev-recall-transport-mcp",
        "meok-vehicle-handover-mcp", "meok-fors-clocs-mcp",
        "meok-dvsa-olicence-mcp", "meok-allmi-hiab-mcp",
        "meok-cpa-contract-lift-mcp", "meok-eu-mobility-package-mcp",
        "meok-nhvr-australia-mcp", "meok-transport-canada-hos-mcp",
        "meok-iru-tir-international-mcp", "meok-iata-dgr-air-cargo-mcp",
        "meok-imo-marpol-marine-mcp",
    }
    assert expected.issubset(set(MEOK_COMPLIANCE_TO_AI_ACT_MAP.keys()))


def test_attestation_chain_signed():
    r = _call(crosswalk_to_ai_act, source_mcp="meok-tacho-audit-mcp")
    assert r["issuer"] == "meok-haulage-governance-bridge-mcp"
    assert "ts" in r and "sig" in r


def test_ai_act_tiers_all_4_present():
    assert set(AI_ACT_RISK_TIERS.keys()) == {"unacceptable", "high", "limited", "minimal"}


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
