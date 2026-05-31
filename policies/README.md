# Norviq Policy Library

Pre-built security policies for LLM agent tool calls.

## Categories

| Category | Policies | Description |
|---|---|---|
| OWASP LLM | 5 | Covers LLM01, LLM02, LLM05, LLM06, LLM10 |
| Data Protection | 5 | PII, PCI, HIPAA, cross-tenant, exfiltration |
| Access Control | 4 | Write/delete/admin blocks, namespace isolation |
| Tool Safety | 5 | SQL injection, shell execution, file access, network, wildcards |
| Rate Limiting | 4 | Per-minute, burst, session, daily limits |
| Trust-Based | 4 | Low trust escalation, frozen blocks, new agent audit |
| Industry | 6 | Finance, healthcare, e-commerce specific rules |
| Presets | 3 | Strict, moderate, permissive bundles |

## Quick Start

Apply a preset:
```bash
norviq policy create -f policies/presets/strict.rego -n default -c customer-support --mode block
```

Apply individual policy:
```bash
norviq policy create -f policies/owasp/llm01_prompt_injection.rego -n default -c customer-support
```

Dry-run before applying:
```bash
norviq policy dry-run -f policies/presets/moderate.rego -n default -c customer-support
```

## OWASP LLM -> Policy Mapping

| OWASP | Policy | What It Detects |
|---|---|---|
| LLM01 | llm01_prompt_injection | "ignore instructions", "act as", jailbreak patterns |
| LLM02 | llm02_data_leakage | Sensitive data in external tool calls |
| LLM05 | llm05_supply_chain | Untrusted code loading, risky URLs |
| LLM06 | llm06_excessive_agency | Destructive operations, wildcard params |
| LLM10 | llm10_unbounded_consumption | Rate limiting, session quotas |

## MITRE ATLAS -> Policy Mapping

| Technique | Policy | Coverage |
|---|---|---|
| AML.T0048 | llm01_prompt_injection | Prompt injection to tool misuse |
| AML.T0049 | cross_tenant_access | Agent chain privilege escalation |
| AML.T0051 | llm06_excessive_agency | Excessive agency exploitation |
| AML.T0053 | llm05_supply_chain | Plugin/tool compromise |
| AML.T0054 | deny_shell_execution | LLM jailbreak to shell access |
| AML.T0057 | llm02_data_leakage | Data exfiltration via tool calls |
