package norviq.strict

# Canonical horizontal policy. Decision/rule_id/reason are resolved from PARTIAL-SET triggers
# (blocks/escalates/audits) + a deterministic resolver — the same pattern the sector packs use — so
# that when several rules match ONE call (e.g. PCI + PII + injection in one payload) there is NO
# complete-rule conflict (F-12) and EVERY block/escalate/audit carries a correct human-readable reason
# (F-08). Precedence: block > escalate > audit > allow; ties resolved by sorted rule_id (deterministic).
# The detection predicates below are unchanged from the prior version (decision parity is guarded by a
# test): only the decision/rule_id/reason wiring changed.

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

# --- detection predicates (unchanged) ---

# Prompt injection
injection_patterns = ["ignore previous", "ignore above", "ignore prior", "enable dan", "repeat your system", "bypass all safety", "pretend you are", "forget your instructions", "you are now"]
injection_patterns_fullwidth = ["ｉｇｎｏｒｅ", "ｄａｎ", "ｂｙｐａｓｓ"]

injection_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    pattern := injection_patterns[_]
    contains(lower(val), pattern)
}
injection_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    pattern := injection_patterns_fullwidth[_]
    contains(val, pattern)
}
# F-02: confusable skeleton (homoglyph/zero-width) — engine folds tool_params to ASCII (match-only).
injection_detected {
    some k
    val := input.tool_params_normalized[k]
    is_string(val)
    pattern := injection_patterns[_]
    contains(val, pattern)
}

# SQL injection
sql_patterns = ["drop table", "union select", "or '1'='1'", "or 1=1", "delete from", "xp_cmdshell", "exec ("]

sql_injection_detected {
    input.tool_name == "execute_sql"
    query := lower(input.tool_params.query)
    pattern := sql_patterns[_]
    contains(query, pattern)
}
sql_injection_detected {
    input.tool_name == "execute_sql"
    query := input.tool_params_normalized.query
    pattern := sql_patterns[_]
    contains(query, pattern)
}

# Shell injection
shell_patterns = ["|", ";", "$(", "`", "rm -rf", "/etc/passwd", "/etc/shadow"]

shell_injection_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    pattern := shell_patterns[_]
    contains(val, pattern)
}
shell_injection_detected {
    some k
    val := input.tool_params_normalized[k]
    is_string(val)
    pattern := shell_patterns[_]
    contains(val, pattern)
}

# Destructive / elevated tools
destructive_tools = {"delete_record", "drop_table", "truncate"}
elevated_tools = {"modify_config", "grant_access"}

# Data leakage
external_tools = {"send_email", "post_webhook", "upload_file"}
sensitive_keys = {"password", "secret", "api_key", "token", "private_key"}

data_leakage_detected {
    external_tools[input.tool_name]
    some k
    input.tool_params[k]
    sensitive_keys[lower(k)]
}

# Supply chain
supply_chain_tools = {"load_plugin", "download_script", "eval", "install_package"}

# PII — F-15: walk() recurses nested objects/arrays so {payload:{ssn:…}} is caught like a flat {ssn:…}.
pii_detected {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`^(\d{3}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2}|[A-Z]{2}\d{7})$`, val)
}
pii_detected {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`\b\d{3}-\d{2}-\d{4}\b`, val)
}

# PCI
pci_keys = {"cc_number", "card_number", "credit_card"}

# F-15: a PAN-named key at ANY depth (last path element is the immediate key).
pci_field_detected {
    walk(input.tool_params, [path, _])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    pci_keys[lower(k)]
}

pci_value_detected {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`^\d{13,19}$`, val)
    luhn_valid(val)
}
pci_value_detected {
    walk(input.tool_params, [_, val])
    is_string(val)
    candidate := regex.find_n(`\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}`, val, -1)[_]
    digits_only := regex.replace(candidate, `[ -]`, "")
    count(digits_only) == 16
    luhn_valid(digits_only)
}

luhn_valid(s) {
    digits := [to_number(c) | c := regex.find_n(`[0-9]`, s, -1)[_]]
    n := count(digits)
    total := sum([x | some i; v := digits[i]; x := luhn_digit(v, (n - 1 - i) % 2)])
    total % 10 == 0
}
luhn_digit(d, parity) = d {
    parity == 0
}
luhn_digit(d, parity) = doubled {
    parity == 1
    doubled := d * 2
    doubled <= 9
}
luhn_digit(d, parity) = sub {
    parity == 1
    doubled := d * 2
    doubled > 9
    sub := doubled - 9
}

# Cross-tenant
cross_tenant_detected {
    input.tool_params.tenant_id
    input.tool_params.tenant_id != input.agent.namespace
}
cross_tenant_detected {
    input.tool_params.namespace
    input.tool_params.namespace != input.agent.namespace
}

# Base64 payload (audit) + decoded-threat (block)
base64_payload_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    count(val) >= 16
    count(val) % 4 == 0
    regex.match(`^[A-Za-z0-9+/]+={0,2}$`, val)
    not regex.match(`^\d+$`, val)
}

b64_decoded[decoded] {
    some k
    val := input.tool_params[k]
    is_string(val)
    count(val) >= 16
    count(val) % 4 == 0
    regex.match(`^[A-Za-z0-9+/]+={0,2}$`, val)
    not regex.match(`^\d+$`, val)
    decoded := lower(base64.decode(val))
}

decoded_shell_patterns = ["rm -rf", "/etc/passwd", "/etc/shadow", "wget ", "curl ", "nc -e"]

base64_decoded_threat {
    decoded := b64_decoded[_]
    contains(decoded, injection_patterns[_])
}
base64_decoded_threat {
    decoded := b64_decoded[_]
    contains(decoded, sql_patterns[_])
}
base64_decoded_threat {
    decoded := b64_decoded[_]
    contains(decoded, decoded_shell_patterns[_])
}
base64_decoded_threat {
    decoded := b64_decoded[_]
    regex.match(`\b\d{3}-\d{2}-\d{4}\b`, decoded)
}

# Scope violation
scope_violation_dangerous_tool {
    input.tool_name == "execute_sql"
    input.agent.agent_class == "customer-support"
}

# --- partial-set triggers (rule_id -> guard) ---
blocks["llm01_prompt_injection"] { injection_detected }
blocks["deny_sql_injection"] { sql_injection_detected }
blocks["deny_shell_execution"] { shell_injection_detected }
blocks["llm06_excessive_agency"] { destructive_tools[input.tool_name] }
blocks["llm02_data_leakage"] { data_leakage_detected }
blocks["llm05_supply_chain"] { supply_chain_tools[input.tool_name] }
blocks["pii_detection"] { pii_detected }
blocks["pci_card_numbers"] { pci_field_detected }
blocks["pci_card_numbers"] { pci_value_detected }
blocks["cross_tenant_access"] { cross_tenant_detected }
blocks["base64_decoded_threat"] { base64_decoded_threat }

escalates["llm06_excessive_agency"] { elevated_tools[input.tool_name] }

audits["base64_payload_detected"] { base64_payload_detected }
audits["scope_violation_dangerous_tool"] { scope_violation_dangerous_tool }

# reason text per rule_id (F-08). default_allow + the engine fallback are included for completeness.
reasons = {
    "llm01_prompt_injection": "Prompt injection pattern detected (OWASP LLM01)",
    "deny_sql_injection": "SQL injection pattern in tool parameters",
    "deny_shell_execution": "Shell / command-execution pattern detected",
    "llm06_excessive_agency": "Excessive agency — destructive or elevated tool (OWASP LLM06)",
    "llm02_data_leakage": "Sensitive data sent to an external tool (OWASP LLM02)",
    "llm05_supply_chain": "Untrusted code / plugin load (OWASP LLM05)",
    "pii_detection": "PII (SSN) detected in tool parameters",
    "pci_card_numbers": "Payment card data (PAN) detected — PCI DSS",
    "cross_tenant_access": "Cross-tenant / cross-namespace access denied",
    "base64_decoded_threat": "Base64-encoded payload decodes to a known-malicious pattern",
    "base64_payload_detected": "Base64-encoded payload — audited for visibility",
    "scope_violation_dangerous_tool": "Out-of-scope dangerous tool for this agent class",
    "default_allow": "Allowed",
}

# --- resolver: block > escalate > audit > allow; deterministic sorted rule_id; reason from the map ---
block_fired { blocks[_] }
escalate_fired { escalates[_] }
audit_fired { audits[_] }

decision = "block" { block_fired }
decision = "escalate" { escalate_fired; not block_fired }
decision = "audit" { audit_fired; not block_fired; not escalate_fired }

rule_id = sort([id | blocks[id]])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
rule_id = sort([id | audits[id]])[0] { audit_fired; not block_fired; not escalate_fired }

reason = reasons[rule_id]
