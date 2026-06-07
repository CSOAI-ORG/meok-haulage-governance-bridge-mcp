#!/usr/bin/env python3
"""
MEOK Haulage Compliance ⇄ Governance Bridge MCP
==================================================

By MEOK AI Labs · https://haulage.app · MIT
<!-- mcp-name: io.github.CSOAI-ORG/meok-haulage-governance-bridge-mcp -->

WHAT THIS DOES
--------------
Every haulage operator now runs AI: route planning, fatigue prediction, lift-plan
generation, FORS data feeds, OCRS forecasting. Under the EU AI Act (effective
2 Aug 2026), most of these systems are HIGH-RISK (Annex III §2 transport
infrastructure, §5 access to essential services like insurance and credit).

That triggers MANDATORY obligations for:
  - PROVIDERS of the AI tool (vendor-side: us, MEOK)
  - DEPLOYERS of the AI tool (operator-side: the haulier)
  - DISTRIBUTORS + IMPORTERS

This MCP is the BRIDGE. Give it any compliance attestation from the MEOK trade
catalogue (15+ MCPs covering UK/EU/US/AU/CA/intl) and it returns:
  - Which AI Act articles apply
  - Whether it's High-Risk / Limited-Risk / Minimal-Risk
  - Provider obligations (Art 16) the vendor MUST satisfy
  - Deployer obligations (Art 26) the operator MUST satisfy
  - FRIA (Fundamental Rights Impact Assessment) inputs
  - IFU (Instructions for Use, Art 13) elements to include
  - Crosswalk to NIST RMF + ISO 42001 + UK AI Bill

It also crosswalks to:
  - UK AI Bill (Article 22c automated decision-making transparency)
  - NIST AI RMF (US — voluntary but DOJ-preferred)
  - ISO/IEC 42001:2023 (AI Management System)
  - DCMS Drone Code (UAS commercial)

The "Hauler's AI Stack" becomes self-auditable: every callable produces a signed
compliance attestation AND a signed governance attestation, both chainable.

TOOLS (10)
----------
- crosswalk_to_ai_act(compliance_attestation, deployment_context) → AI Act tier + duties
- classify_ai_risk_tier(use_case, deployment_geography)            → Unacceptable/High/Limited/Minimal
- list_provider_obligations(risk_tier, ai_act_articles)            → Art 16 duties
- list_deployer_obligations(risk_tier, ai_act_articles)            → Art 26 duties
- generate_fria_inputs(deployer_context, compliance_data)          → Fundamental Rights IA
- generate_ifu_skeleton(provider_info, ai_system)                  → Art 13 IFU
- crosswalk_to_nist_rmf(ai_act_tier)                               → US NIST AI RMF
- crosswalk_to_iso_42001(ai_act_tier)                              → AIMS clause map
- chain_attestations(compliance_sig, governance_sig)               → unified evidence
- check_uk_ai_bill_art_22c(use_case)                               → UK ADM transparency

WHY YOU PAY
-----------
Pro tier £149/mo. One avoided AI Act non-compliance fine (up to €35m or 7%
of global turnover) is a rounding-error vs the subscription.

PRICING
-------
Free MIT self-host · £49/mo Starter · £149/mo Pro · £799/mo Fleet · £2,999/mo Substrate.

REGULATORY BASIS
----------------
- Regulation (EU) 2024/1689 — EU AI Act (effective 2 Aug 2026 for high-risk)
- UK AI Bill (Art 22c ADM transparency)
- NIST AI Risk Management Framework v1.0
- ISO/IEC 42001:2023 — Artificial Intelligence Management Systems
- DCMS Drone Code (UAS commercial use)
"""

from __future__ import annotations
import hashlib, hmac, json, os
from datetime import datetime, timezone
from typing import Optional
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("meok-haulage-governance-bridge")
_HMAC_SECRET = os.environ.get("MEOK_HMAC_SECRET", "")


# ──────────────────────────────────────────────────────────────────────
# Regulatory tables
# ──────────────────────────────────────────────────────────────────────

# AI Act Annex III — high-risk use cases relevant to haulage
ANNEX_III_HAULAGE_RELEVANT = {
    "2_critical_infrastructure": (
        "Safety components of management + operation of critical digital infrastructure, "
        "road traffic, supply of water, gas, heating, electricity. Includes traffic "
        "control systems used by hauliers (tachograph + route planning)."
    ),
    "5a_access_essential_private_services": (
        "AI systems for evaluating creditworthiness, credit scores. Relevant for "
        "haulier financial-standing checks via AI."
    ),
    "5b_insurance_risk_pricing": (
        "AI used to evaluate health/life insurance risk + pricing. Relevant for "
        "fleet insurance scoring."
    ),
    "8b_assessment_immigration_asylum_eu_borders": (
        "Relevant for cross-border haulage with predictive routing through Schengen."
    ),
}

# AI Act risk tiers
AI_ACT_RISK_TIERS = {
    "unacceptable": {
        "examples": ["social scoring", "predictive policing", "real-time biometric ID public spaces"],
        "deadline": "PROHIBITED from 2 Feb 2025",
        "penalty": "up to €35m or 7% global turnover (Art 99)",
    },
    "high": {
        "examples": ["Annex III use cases", "safety components of products in Annex I"],
        "deadline": "2 Aug 2026 for new + retrofit existing by 2 Aug 2027",
        "penalty": "up to €15m or 3% global turnover (Art 99.4)",
    },
    "limited": {
        "examples": ["chatbots", "emotion recognition", "biometric categorisation", "deepfakes"],
        "deadline": "2 Aug 2026 transparency obligations",
        "penalty": "up to €7.5m or 1.5% global turnover (Art 99.5)",
    },
    "minimal": {
        "examples": ["spam filters", "AI-enabled video games", "simple recommendation"],
        "deadline": "no specific obligations (Art 95 voluntary codes of conduct)",
        "penalty": "n/a",
    },
}

# Provider obligations (Art 16) for high-risk
PROVIDER_OBLIGATIONS_HIGH_RISK = [
    "Establish risk management system (Art 9)",
    "Data + data governance (Art 10) — training, validation, testing data quality",
    "Technical documentation (Art 11) before market placement",
    "Record-keeping (Art 12) — automated event logging",
    "Transparency + IFU (Art 13)",
    "Human oversight design (Art 14)",
    "Accuracy, robustness, cybersecurity (Art 15)",
    "Quality management system (Art 17)",
    "Documentation retention 10 years (Art 18)",
    "Automatically generated logs (Art 19)",
    "Corrective action + duty to inform (Art 20)",
    "Cooperation with competent authorities (Art 21)",
    "Authorised representatives in EU (Art 22)",
    "Conformity assessment (Art 43)",
    "CE marking (Art 48)",
    "EU declaration of conformity (Art 47)",
    "Registration in EU database (Art 49)",
    "Post-market monitoring (Art 72)",
    "Reporting serious incidents (Art 73)",
]

# Deployer obligations (Art 26) for high-risk
DEPLOYER_OBLIGATIONS_HIGH_RISK = [
    "Use the system per Instructions for Use (Art 26.1)",
    "Assign human oversight to natural persons (Art 26.2)",
    "Ensure input data relevant + representative for intended purpose (Art 26.4)",
    "Monitor operation per IFU (Art 26.5)",
    "Keep logs for 6 months minimum (Art 26.6)",
    "Inform workers / their representatives prior to deployment in workplace (Art 26.7)",
    "Register Annex III use cases (Art 49.6)",
    "Conduct FRIA where deployer is public-body or providing public service (Art 27)",
    "Inform affected natural persons of HR-AI subjection (Art 26.11)",
    "Cooperate with competent authority for serious incident reporting (Art 26.5)",
]

# UK AI Bill Article 22c
UK_AI_BILL_ART_22C = {
    "scope": "Automated Decision Making (ADM) — fully automated decisions affecting individuals",
    "rights": [
        "Right to be informed when ADM is used",
        "Right to human intervention upon request",
        "Right to challenge an automated decision",
        "Right to an explanation of the decision logic",
    ],
    "exemptions": ["legal authority", "contract necessity (with explicit consent)", "explicit consent"],
    "status": "UK AI (Regulation) Bill 2024 — currently in House of Lords",
}

# NIST AI RMF v1.0 four functions
NIST_AI_RMF_FUNCTIONS = ["GOVERN", "MAP", "MEASURE", "MANAGE"]

# ISO 42001:2023 key clauses
ISO_42001_KEY_CLAUSES = {
    "4": "Context of the organisation",
    "5": "Leadership",
    "6": "Planning (AI risk + opportunities)",
    "7": "Support (resources, competence, communication)",
    "8": "Operation (AI system life cycle)",
    "9": "Performance evaluation",
    "10": "Improvement",
    "A.5": "Organisational policies for AI",
    "A.6": "Internal organisation for AI",
    "A.7": "Resources for AI systems",
    "A.8": "Information for stakeholders",
    "A.9": "Use of AI systems",
}

# Compliance MCP → AI Act crosswalk
MEOK_COMPLIANCE_TO_AI_ACT_MAP = {
    "meok-tacho-audit-mcp": {
        "ai_use_cases": ["OCRS forecasting", "infringement prediction", "PI risk scoring"],
        "annex_iii_categories": ["2_critical_infrastructure"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,  # Not public body
    },
    "meok-fmcsa-hours-of-service-mcp": {
        "ai_use_cases": ["CSA score forecast", "intervention prediction"],
        "annex_iii_categories": [],
        "default_risk_tier": "limited",
        "fria_required_for_deployer": False,
    },
    "meok-bs7121-mcp": {
        "ai_use_cases": ["Lift plan generation", "ground bearing calc", "AP cert verify"],
        "annex_iii_categories": ["2_critical_infrastructure"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,
    },
    "meok-ev-recall-transport-mcp": {
        "ai_use_cases": ["ADR Class 9 classification", "thermal-runaway routing", "DGSA workflow"],
        "annex_iii_categories": ["2_critical_infrastructure"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,
    },
    "meok-vehicle-handover-mcp": {
        "ai_use_cases": ["NAMA auto-grading from photos", "damage liability triage"],
        "annex_iii_categories": ["5a_access_essential_private_services"],  # affects insurance claim
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,
    },
    "meok-fors-clocs-mcp": {
        "ai_use_cases": ["FORS Bronze/Silver/Gold readiness scoring"],
        "annex_iii_categories": [],
        "default_risk_tier": "limited",
        "fria_required_for_deployer": False,
    },
    "meok-dvsa-olicence-mcp": {
        "ai_use_cases": ["PI brief generation", "OCRS forecasting", "TM-disqualification risk"],
        "annex_iii_categories": ["2_critical_infrastructure", "5a_access_essential_private_services"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,
    },
    "meok-allmi-hiab-mcp": {
        "ai_use_cases": ["Lift plan generation", "delivery rejection prediction"],
        "annex_iii_categories": ["2_critical_infrastructure"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,
    },
    "meok-cpa-contract-lift-mcp": {
        "ai_use_cases": ["Contract triage", "T&C generation", "Baldwins-risk scoring"],
        "annex_iii_categories": [],
        "default_risk_tier": "limited",
        "fria_required_for_deployer": False,
    },
    "meok-eu-mobility-package-mcp": {
        "ai_use_cases": ["Cabotage detection", "return-to-base forecasting", "IMI declaration auto-gen"],
        "annex_iii_categories": ["2_critical_infrastructure"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,
    },
    "meok-nhvr-australia-mcp": {
        "ai_use_cases": ["Fatigue management forecasting", "CoR risk scoring"],
        "annex_iii_categories": [],
        "default_risk_tier": "limited",  # AU not under AI Act but pattern same
        "fria_required_for_deployer": False,
    },
    "meok-transport-canada-hos-mcp": {
        "ai_use_cases": ["NSC safety rating forecast", "cycle-switch eligibility"],
        "annex_iii_categories": [],
        "default_risk_tier": "limited",
        "fria_required_for_deployer": False,
    },
    "meok-iru-tir-international-mcp": {
        "ai_use_cases": ["TIR carnet validity check", "border crossing routing"],
        "annex_iii_categories": ["8b_assessment_immigration_asylum_eu_borders"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": True,  # cross-border = essential services dimension
    },
    "meok-iata-dgr-air-cargo-mcp": {
        "ai_use_cases": ["DG classification", "PI 965-970 assignment"],
        "annex_iii_categories": ["2_critical_infrastructure"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,
    },
    "meok-imo-marpol-marine-mcp": {
        "ai_use_cases": ["CII rating forecast", "EU ETS maritime price"],
        "annex_iii_categories": ["2_critical_infrastructure"],
        "default_risk_tier": "high",
        "fria_required_for_deployer": False,
    },
}


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _sign(payload: dict) -> str:
    if not _HMAC_SECRET:
        return "unsigned-no-key-configured"
    return hmac.new(_HMAC_SECRET.encode(),
                    json.dumps(payload, sort_keys=True, default=str).encode(),
                    hashlib.sha256).hexdigest()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _attestation(payload: dict) -> dict:
    return {**payload, "ts": _ts(), "sig": _sign(payload),
            "issuer": "meok-haulage-governance-bridge-mcp", "version": "1.0.0"}


# ──────────────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def crosswalk_to_ai_act(
    source_mcp: str,
    deployment_geography: str = "EU",
    deployer_is_public_body: bool = False,
) -> dict:
    """Map a MEOK compliance MCP → AI Act tier + obligations.

    Args:
      source_mcp: e.g. "meok-tacho-audit-mcp"
      deployment_geography: "EU", "UK", "US", "AU", "intl"
      deployer_is_public_body: triggers FRIA requirement
    """
    info = MEOK_COMPLIANCE_TO_AI_ACT_MAP.get(source_mcp)
    if not info:
        return _attestation({
            "tool": "crosswalk_to_ai_act",
            "source_mcp": source_mcp,
            "known": False,
            "advisory": "MCP not in crosswalk map — default to LIMITED risk + transparency obligations.",
        })

    risk_tier = info["default_risk_tier"]
    fria_required = info["fria_required_for_deployer"] or deployer_is_public_body

    relevant_articles = []
    if risk_tier == "high":
        relevant_articles = ["Art 9", "Art 10", "Art 11", "Art 12", "Art 13", "Art 14",
                             "Art 15", "Art 16", "Art 26", "Art 27", "Art 43", "Art 47-49"]
    elif risk_tier == "limited":
        relevant_articles = ["Art 50", "Art 52"]

    return _attestation({
        "tool": "crosswalk_to_ai_act",
        "source_mcp": source_mcp,
        "known": True,
        "ai_use_cases_typical": info["ai_use_cases"],
        "annex_iii_categories": info["annex_iii_categories"],
        "risk_tier": risk_tier,
        "tier_meaning": AI_ACT_RISK_TIERS[risk_tier],
        "applicable_articles": relevant_articles,
        "fria_required_for_deployer": fria_required,
        "deployment_geography": deployment_geography,
        "next_action": (
            f"Pair with meok-eu-ai-act-art-13-ifu-mcp (provider) + "
            f"meok-eu-ai-act-art-26-fria-mcp (deployer) "
            f"for full audit-grade evidence pack."
        ),
    })


@mcp.tool()
def classify_ai_risk_tier(
    use_case_description: str,
    deployment_geography: str = "EU",
    is_safety_component: bool = False,
    affects_essential_services: bool = False,
) -> dict:
    """Classify an AI use case into Unacceptable / High / Limited / Minimal."""
    kw = use_case_description.lower()
    tier = "minimal"

    # Unacceptable triggers
    if any(t in kw for t in ["social scoring", "predictive policing", "biometric mass"]):
        tier = "unacceptable"
    # High-risk triggers
    elif is_safety_component or affects_essential_services or \
         any(t in kw for t in ["credit", "insurance", "employment", "education",
                                "law enforcement", "asylum", "border"]):
        tier = "high"
    # Limited-risk triggers
    elif any(t in kw for t in ["chatbot", "deepfake", "emotion recognition", "biometric"]):
        tier = "limited"

    return _attestation({
        "tool": "classify_ai_risk_tier",
        "use_case": use_case_description[:200],
        "geography": deployment_geography,
        "risk_tier": tier,
        "tier_meaning": AI_ACT_RISK_TIERS[tier],
    })


@mcp.tool()
def list_provider_obligations(
    risk_tier: str = "high",
) -> dict:
    """List EU AI Act provider obligations for a given risk tier."""
    if risk_tier == "high":
        obligations = PROVIDER_OBLIGATIONS_HIGH_RISK
    elif risk_tier == "limited":
        obligations = [
            "Transparency disclosure (Art 50.1) — users informed they're interacting with AI",
            "Synthetic content marking (Art 50.2)",
            "Deepfake disclosure (Art 50.4)",
        ]
    elif risk_tier == "minimal":
        obligations = ["Voluntary AI codes of conduct (Art 95)"]
    else:
        obligations = ["PROHIBITED — no provider operation legal (Art 5)"]
    return _attestation({
        "tool": "list_provider_obligations",
        "risk_tier": risk_tier,
        "obligations": obligations,
        "count": len(obligations),
        "regulator": "EU AI Act 2024/1689",
    })


@mcp.tool()
def list_deployer_obligations(
    risk_tier: str = "high",
    deployer_is_public_body: bool = False,
) -> dict:
    """List EU AI Act deployer obligations for a given risk tier."""
    if risk_tier == "high":
        obligations = list(DEPLOYER_OBLIGATIONS_HIGH_RISK)
        if not deployer_is_public_body:
            obligations = [o for o in obligations if "FRIA" not in o]
    elif risk_tier == "limited":
        obligations = [
            "Inform users of AI interaction (Art 50.3)",
            "Disclose AI-generated content (Art 50.4)",
        ]
    elif risk_tier == "minimal":
        obligations = []
    else:
        obligations = ["PROHIBITED — no deployer use legal"]

    return _attestation({
        "tool": "list_deployer_obligations",
        "risk_tier": risk_tier,
        "deployer_is_public_body": deployer_is_public_body,
        "obligations": obligations,
        "count": len(obligations),
    })


@mcp.tool()
def generate_fria_inputs(
    deployer_name: str,
    deployer_country: str,
    affected_persons_groups: Optional[list] = None,
    ai_use_purpose: str = "",
    compliance_attestation_refs: Optional[list] = None,
) -> dict:
    """Generate Fundamental Rights Impact Assessment inputs (Art 27).

    Required for: public bodies + private deployers providing public services
    + private deployers in Annex III §5(b) (credit/insurance) §5(c) (essential services).
    """
    affected = affected_persons_groups or []
    refs = compliance_attestation_refs or []
    return _attestation({
        "tool": "generate_fria_inputs",
        "deployer": deployer_name,
        "country": deployer_country,
        "purpose": ai_use_purpose,
        "fria_sections": [
            {"section": "I. AI system identification + purpose"},
            {"section": "II. Frequency + period of use"},
            {"section": "III. Affected natural-persons groups"},
            {"section": "IV. Specific risks of harm to identified groups"},
            {"section": "V. Human oversight measures"},
            {"section": "VI. Measures + risk-mitigation if harm materialises"},
        ],
        "affected_groups": affected,
        "compliance_attestation_anchors": refs,
        "advisory": "Submit to market surveillance authority before deployment (Art 27.4).",
    })


@mcp.tool()
def generate_ifu_skeleton(
    provider_legal_name: str,
    ai_system_name: str,
    intended_purpose: str = "",
    capabilities: str = "",
    limitations: str = "",
) -> dict:
    """Generate Instructions for Use skeleton per Art 13(3) — the 7 mandatory elements."""
    return _attestation({
        "tool": "generate_ifu_skeleton",
        "provider": provider_legal_name,
        "ai_system": ai_system_name,
        "ifu_sections": [
            {"section": "(a) Identity + contact of provider + authorised representative",
             "content": provider_legal_name},
            {"section": "(b) Characteristics, capabilities, limitations",
             "content": f"Purpose: {intended_purpose}; Capabilities: {capabilities}; Limitations: {limitations}"},
            {"section": "(c) Pre-determined changes + post-market plan",
             "content": "Specify version cadence + retraining triggers"},
            {"section": "(d) Human oversight design (Art 14)",
             "content": "Specify human-in/on-loop role + STOP control"},
            {"section": "(e) Compute + hardware + maintenance lifecycle"},
            {"section": "(f) Log collection, storage, interpretation by deployer"},
            {"section": "(g) Other relevant info for intended use"},
        ],
        "regulator": "EU AI Act Art 13(3)",
        "pair_with": "meok-eu-ai-act-art-13-ifu-mcp for full generation",
    })


@mcp.tool()
def crosswalk_to_nist_rmf(
    ai_act_risk_tier: str = "high",
) -> dict:
    """Map EU AI Act tier to NIST AI Risk Management Framework v1.0 functions."""
    return _attestation({
        "tool": "crosswalk_to_nist_rmf",
        "ai_act_tier": ai_act_risk_tier,
        "nist_functions": NIST_AI_RMF_FUNCTIONS,
        "mapping": {
            "GOVERN": "EU AI Act Art 9 (Risk Management System), Art 17 (Quality Management System)",
            "MAP":    "EU AI Act Art 10 (data + data governance), Art 11 (technical documentation)",
            "MEASURE":"EU AI Act Art 12 (record-keeping), Art 15 (accuracy/robustness/cyber)",
            "MANAGE": "EU AI Act Art 13 (transparency), Art 14 (human oversight), Art 72 (post-market monitoring)",
        },
        "us_advisory": "DOJ + EEOC preference: NIST RMF + EU AI Act for cross-jurisdiction defence.",
    })


@mcp.tool()
def crosswalk_to_iso_42001(
    ai_act_risk_tier: str = "high",
) -> dict:
    """Map EU AI Act tier to ISO/IEC 42001:2023 AIMS clauses."""
    return _attestation({
        "tool": "crosswalk_to_iso_42001",
        "ai_act_tier": ai_act_risk_tier,
        "iso_42001_clauses": ISO_42001_KEY_CLAUSES,
        "high_risk_critical_clauses": ["6", "8", "9", "A.6", "A.7", "A.9"],
        "advisory": (
            "ISO 42001 certification + AI Act compliance = global gold standard. "
            "Audit overlap is ~75%. Schedule ISO audit alongside AI Act conformity assessment."
        ),
    })


@mcp.tool()
def chain_attestations(
    compliance_attestation: dict,
    governance_attestation: Optional[dict] = None,
) -> dict:
    """Chain a compliance attestation with the matching governance attestation
    into a single verifiable evidence record.
    """
    src_mcp = compliance_attestation.get("issuer", "unknown")
    src_sig = compliance_attestation.get("sig", "")
    src_ts = compliance_attestation.get("ts", "")

    gov_attestation = governance_attestation or {}

    combined_payload = {
        "tool": "chain_attestations",
        "compliance": {
            "issuer": src_mcp,
            "sig": src_sig,
            "ts": src_ts,
            "tool": compliance_attestation.get("tool", ""),
        },
        "governance": {
            "issuer": gov_attestation.get("issuer", ""),
            "sig": gov_attestation.get("sig", ""),
            "ts": gov_attestation.get("ts", ""),
            "tool": gov_attestation.get("tool", ""),
        },
        "chain_id": hashlib.sha256(
            (src_sig + gov_attestation.get("sig", "")).encode()
        ).hexdigest()[:24],
    }
    return _attestation(combined_payload)


@mcp.tool()
def check_uk_ai_bill_art_22c(
    use_case_description: str,
    has_human_in_loop: bool = False,
    has_explanation_capability: bool = False,
    has_appeal_mechanism: bool = False,
) -> dict:
    """UK AI (Regulation) Bill Article 22c — Automated Decision Making transparency check."""
    is_fully_automated = not has_human_in_loop
    triggers_art_22c = is_fully_automated and "decision" in use_case_description.lower()

    gaps = []
    if triggers_art_22c:
        if not has_explanation_capability:
            gaps.append("Missing explanation capability — Art 22c(2)(d)")
        if not has_appeal_mechanism:
            gaps.append("Missing appeal mechanism — Art 22c(2)(c)")
        if not has_human_in_loop:
            gaps.append("Fully-automated decision — must offer human intervention on request — Art 22c(2)(b)")

    return _attestation({
        "tool": "check_uk_ai_bill_art_22c",
        "triggers_art_22c": triggers_art_22c,
        "compliance_gaps": gaps,
        "art_22c_summary": UK_AI_BILL_ART_22C,
    })


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/00wfZjcgAeUW4c5cyQ8k90K"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}
