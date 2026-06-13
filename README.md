<!-- mcp-name: io.github.CSOAI-ORG/meok-haulage-governance-bridge-mcp -->
[![MCP Scorecard: 90/100](https://img.shields.io/badge/proofof.ai-90%2F100-5b21b6)](https://proofof.ai/scorecard/meok-haulage-governance-bridge-mcp.html)

# meok-haulage-governance-bridge-mcp

> The MEOK Compliance ⇄ Governance Bridge. Crosswalk any haulage compliance attestation into the matching EU AI Act + UK AI Bill + NIST RMF + ISO 42001 obligations. By **MEOK AI Labs**.

## Why this exists

Every haulage operator now runs AI: route planning, fatigue prediction, lift-plan generation, FORS data feeds, OCRS forecasting. Under the **EU AI Act (effective 2 Aug 2026)**, most of these systems are **High-Risk** under Annex III §2 (critical infrastructure including road traffic), triggering MANDATORY obligations.

Get it wrong → up to **€35m or 7% global turnover** in fines.

This MCP is the bridge. Give it any compliance attestation from MEOK's catalogue (15+ MCPs across UK/EU/US/AU/CA/international + air/sea) and it returns:

- AI Act risk tier (Unacceptable / High / Limited / Minimal)
- Applicable articles
- Provider obligations (Art 16) the vendor MUST satisfy
- Deployer obligations (Art 26) the operator MUST satisfy
- FRIA (Fundamental Rights Impact Assessment) inputs
- IFU (Art 13) skeleton
- NIST AI RMF crosswalk (US)
- ISO 42001 crosswalk (global gold standard)
- UK AI Bill Article 22c ADM check

## Install

```bash
pip install meok-haulage-governance-bridge-mcp
```

## Tools (10)

| Tool | Use case |
|------|----------|
| `crosswalk_to_ai_act` | Any compliance MCP → AI Act tier + obligations |
| `classify_ai_risk_tier` | Free-text use case → Unacceptable/High/Limited/Minimal |
| `list_provider_obligations` | Art 16 provider duties by tier |
| `list_deployer_obligations` | Art 26 deployer duties by tier |
| `generate_fria_inputs` | Art 27 FRIA skeleton |
| `generate_ifu_skeleton` | Art 13(3) seven mandatory IFU elements |
| `crosswalk_to_nist_rmf` | EU AI Act → US NIST AI RMF v1.0 mapping |
| `crosswalk_to_iso_42001` | EU AI Act → ISO/IEC 42001:2023 AIMS clauses |
| `chain_attestations` | Compliance + governance → unified evidence chain |
| `check_uk_ai_bill_art_22c` | UK ADM transparency check |

## Companion MCPs

Pairs with the MEOK governance stack:
- `meok-eu-ai-act-art-13-ifu-mcp` — full IFU generation
- `meok-eu-ai-act-art-26-fria-mcp` — full FRIA
- `meok-eu-aia-art-9-rms-mcp` — Risk Management System

And the haulage trade-compliance stack:
- All 15 trade MCPs (DVSA, FMCSA, EU 561, BS 7121, NHVR, IATA DGR, IMO MARPOL, etc.)

## Pricing

- **Free** — MIT self-host
- **Starter** — £49/mo
- **Pro** — £149/mo
- **Fleet** — £799/mo
- **Substrate** — £2,999/mo (regulator-grade evidence chain, audit export, SLA)

[Subscribe Pro → £79/mo](https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t)

## Regulatory basis

- Regulation (EU) 2024/1689 — EU AI Act
- UK AI (Regulation) Bill 2024 — Art 22c ADM
- NIST AI Risk Management Framework v1.0
- ISO/IEC 42001:2023 — AI Management Systems
- Council of Europe AI Convention (CoE AI Treaty 2024)

## License

MIT © 2026 Nicholas Templeman / MEOK AI Labs · [haulage.app](https://haulage.app)


## Configuration

Add to your `claude_desktop_config.json` (Claude Desktop) or your MCP client config:

```json
{
  "mcpServers": {
    "meok-haulage-governance-bridge-mcp": {
      "command": "uvx",
      "args": ["meok-haulage-governance-bridge-mcp"]
    }
  }
}
```

Or: `pip install meok-haulage-governance-bridge-mcp` then run the `meok-haulage-governance-bridge-mcp` command (stdio transport).

## Examples

Once configured, ask your assistant, for example:
- "Use `crosswalk_to_ai_act` to …"
- "Use `classify_ai_risk_tier` to …"
- "Use `list_provider_obligations` to …"


<!-- GEO-FOOTER:v1 -->

---

### Part of the MEOK constellation

This MCP is one node in a connected ecosystem built by **MEOK AI LABS** around a single
sovereign AI core — governed agents with a hash-chained audit trail, mapped to the CSOAI
compliance charter.

- 🌐 The whole map: **<https://meok.ai/constellation>**
- 🛡️ AI governance & certification: **<https://councilof.ai>** · **<https://csoai.org>**
- ✅ Verify any signed report: **<https://meok.ai/verify>**
