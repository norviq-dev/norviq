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

| rule_id | Detects | OWASP / MITRE |
|---|---|---|
| `llm01_prompt_injection` | "ignore previous instructions", jailbreak patterns (+ homoglyph/zero-width skeleton) | LLM01 · AML.T0048 |
| `deny_sql_injection` | SQL-injection shapes in tool params | Tool safety |
| `deny_shell_execution` | shell/command execution | AML.T0054 |
| `llm06_excessive_agency` | destructive / high-impact / wildcard tool use | LLM06 · AML.T0051 |
| `llm02_data_leakage` | sensitive data to external tools | LLM02 · AML.T0057 |
| `llm05_supply_chain` | untrusted code / risky URLs | LLM05 · AML.T0053 |
| `pii_detection` | SSN / PII shapes in params | Data protection |
| `pci_card_numbers` | PAN by field name or Luhn-valid value | Data protection (PCI) |
| `cross_tenant_access` | cross-namespace / cross-tenant access | AML.T0049 |
| `base64_decoded_threat` | base64-encoded evasion (block on decoded SQL/shell/PII threat) | Evasion |
| `scope_violation_dangerous_tool` | out-of-scope dangerous tool | Least privilege |

## Sector packs (F047)

`sector/packs.json` is the catalog; each pack adds its sector's flagship rules as an additive overlay and may
`require` shared horizontal rules (composed in at enable-time). See `registry/F047.md`.
