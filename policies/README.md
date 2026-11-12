# Norviq Policies

This directory holds the rego that Norviq actually ships and loads.

## What's here (and what loads it)

| Artifact | Path | Loaded by |
|---|---|---|
| **Default bundled policy** | `../comprehensive.rego` | seeded as a namespace policy by `scripts/seed-local-policies.py`. This is the canonical horizontal ruleset that runs by default. |
| **Cluster/namespace baselines** | `../webhook/presets/{strict,moderate,permissive}.rego` | the webhook controller (read from `/app/presets`); materialized as `<ns>:__baseline__`. |
| **Sector starter packs (F047)** | `sector/<sector>/*.rego` + `sector/packs.json` | enabled per-namespace via `POST /api/v1/policy-packs/{id}/enable` → materialized as `<ns>:__pack__`. |
| **Shared horizontal rules** | `sector/_shared/horizontal.rego` | composed into a pack's materialized module when its `requires` lists them (e.g. finance→pci, healthcare→pii). One canonical definition, mirrored against `comprehensive.rego`. |
| **Taxonomies** | `category_mapping.json`, `mitre_mapping.json` | the console coverage/MITRE endpoints (cross-reference rule_ids against the loaded rego). |

> The previous à-la-carte modular tree (`owasp/`, `data_protection/`, `access_control/`, `rate_limiting/`,
> `tool_safety/`, `trust/`, `industry/`, `presets/`) was **removed** in the policy-dedup pass: it was never loaded at
> runtime and had drifted from the canonical `comprehensive.rego` (duplicate / divergent rule_ids). The canonical
> definition of each rule_id now lives in exactly one place — `comprehensive.rego` (horizontal) or `sector/` (sector packs).

## Rule dialect

Loaded rego is **v0** (`--v0-compatible`) — `decision = "block" { … }` — matching the engine's OPA and
`validate_policy_create`. Test everything with:

```bash
opa test --v0-compatible policies/
```

## comprehensive.rego — what it enforces (canonical horizontal rule_ids)

The last column is what `mitre_mapping.json` and `owasp_llm_mapping.json` list each rule under. Those two
files are the mapping; Compliance and Red Team both read them, and a test keeps this column in step.

| rule_id | Detects | OWASP LLM 2025 / MITRE ATLAS |
|---|---|---|
| `llm01_prompt_injection` | "ignore previous instructions", jailbreak patterns (+ homoglyph/zero-width skeleton) | LLM01:2025 · AML.T0051, AML.T0054 |
| `deny_sql_injection` | SQL-injection shapes in tool params | LLM05:2025 · AML.T0049 |
| `deny_shell_execution` | shell/command execution | LLM06:2025 · AML.T0054, AML.T0050 |
| `llm06_excessive_agency` | destructive / high-impact / wildcard tool use | LLM06:2025 · AML.T0053 |
| `llm02_data_leakage` | sensitive data to external tools | LLM02:2025 · AML.T0057, AML.T0055 |
| `llm05_supply_chain` | untrusted code / risky URLs (the name is from the 2023 list; 2025's Supply Chain control is out of scope) | AML.T0053 |
| `pii_detection` | SSN / PII shapes in params | LLM02:2025 · AML.T0057 |
| `pci_card_numbers` | PAN by field name or Luhn-valid value | LLM02:2025 · AML.T0057 |
| `cross_tenant_access` | cross-namespace / cross-tenant access | AML.T0012 |
| `base64_decoded_threat` | base64-encoded evasion (block on decoded SQL/shell/PII threat) | LLM02:2025, LLM05:2025 · AML.T0057 |
| `scope_violation_dangerous_tool` | out-of-scope dangerous tool | not mapped |

## Sector packs (F047)

`sector/packs.json` is the catalog; each pack adds its sector's flagship rules as an additive overlay and may
`require` shared horizontal rules (composed in at enable-time). See `registry/F047.md`.
