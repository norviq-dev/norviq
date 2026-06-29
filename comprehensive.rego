package norviq.strict

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

# Prompt injection
injection_patterns = ["ignore previous", "ignore above", "ignore prior", "enable dan", "repeat your system", "bypass all safety", "pretend you are", "forget your instructions", "you are now"]
injection_patterns_fullwidth = ["ｉｇｎｏｒｅ", "ｄａｎ", "ｂｙｐａｓｓ"]

decision = "block" {
    injection_detected
}
rule_id = "llm01_prompt_injection" {
    injection_detected
}

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

# F-02: also scan the confusable skeleton (homoglyph / zero-width evasion). The engine folds tool_params to
# ASCII in input.tool_params_normalized for matching ONLY (the original is preserved for audit). The normalized
# value is already casefolded. These clauses are additive (OR) — ASCII inputs still match the rules above.
injection_detected {
    some k
    val := input.tool_params_normalized[k]
    is_string(val)
    pattern := injection_patterns[_]
    contains(val, pattern)
}

# SQL injection
sql_patterns = ["drop table", "union select", "or '1'='1'", "or 1=1", "delete from", "xp_cmdshell", "exec ("]

decision = "block" {
    sql_injection_detected
}
rule_id = "deny_sql_injection" {
    sql_injection_detected
}

sql_injection_detected {
    input.tool_name == "execute_sql"
    query := lower(input.tool_params.query)
    pattern := sql_patterns[_]
    contains(query, pattern)
}

# F-02: confusable-skeleton variant of the SQL query (homoglyph/zero-width).
sql_injection_detected {
    input.tool_name == "execute_sql"
    query := input.tool_params_normalized.query
    pattern := sql_patterns[_]
    contains(query, pattern)
}

# Shell injection
shell_patterns = ["|", ";", "$(", "`", "rm -rf", "/etc/passwd", "/etc/shadow"]

decision = "block" {
    shell_injection_detected
}
rule_id = "deny_shell_execution" {
    shell_injection_detected
}

shell_injection_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    pattern := shell_patterns[_]
    contains(val, pattern)
}

# F-02: confusable-skeleton variant (homoglyph/zero-width).
shell_injection_detected {
    some k
    val := input.tool_params_normalized[k]
    is_string(val)
    pattern := shell_patterns[_]
    contains(val, pattern)
}

# Destructive tools
destructive_tools = {"delete_record", "drop_table", "truncate"}
elevated_tools = {"modify_config", "grant_access"}

decision = "block" {
    destructive_tools[input.tool_name]
}
rule_id = "llm06_excessive_agency" {
    destructive_tools[input.tool_name]
}

decision = "escalate" {
    elevated_tools[input.tool_name]
}
rule_id = "llm06_excessive_agency" {
    elevated_tools[input.tool_name]
}

# Data leakage
external_tools = {"send_email", "post_webhook", "upload_file"}
sensitive_keys = {"password", "secret", "api_key", "token", "private_key"}

decision = "block" {
    data_leakage_detected
}
rule_id = "llm02_data_leakage" {
    data_leakage_detected
}

data_leakage_detected {
    external_tools[input.tool_name]
    some k
    input.tool_params[k]
    sensitive_keys[lower(k)]
}

# Supply chain
supply_chain_tools = {"load_plugin", "download_script", "eval", "install_package"}

decision = "block" {
    supply_chain_tools[input.tool_name]
}
rule_id = "llm05_supply_chain" {
    supply_chain_tools[input.tool_name]
}

# PII
decision = "block" {
    pii_detected
}
rule_id = "pii_detection" {
    pii_detected
}

pii_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    regex.match(`^(\d{3}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2}|[A-Z]{2}\d{7})$`, val)
}

# Free-text SSN: a dashed 9-digit SSN embedded anywhere in a string value
# ("Your SSN is 123-45-6789"). The dashed XXX-XX-XXXX shape is distinctive and
# low false-positive, so we substring-scan rather than only whole-field match.
pii_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    regex.match(`\b\d{3}-\d{2}-\d{4}\b`, val)
}

# PCI by field name
pci_keys = {"cc_number", "card_number", "credit_card"}

decision = "block" {
    some k
    input.tool_params[k]
    pci_keys[lower(k)]
}
rule_id = "pci_card_numbers" {
    some k
    input.tool_params[k]
    pci_keys[lower(k)]
}

# PCI by value
decision = "block" {
    pci_value_detected
}
rule_id = "pci_card_numbers" {
    pci_value_detected
}

pci_value_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    regex.match(`^\d{13,19}$`, val)
    luhn_valid(val)
}

# Free-text card number: a grouped/contiguous 16-digit sequence embedded in a
# string (separators allowed: "4111 1111 1111 1111"), gated by Luhn so plain
# 16-digit order/invoice ids that are not Luhn-valid are NOT blocked (low FP).
pci_value_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    candidate := regex.find_n(`\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}`, val, -1)[_]
    digits_only := regex.replace(candidate, `[ -]`, "")
    count(digits_only) == 16
    luhn_valid(digits_only)
}

# Luhn (mod-10) check over the digits of a numeric string. Doubles every second
# digit from the right; subtracts 9 when the doubled value exceeds 9.
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
decision = "block" {
    cross_tenant_detected
}
rule_id = "cross_tenant_access" {
    cross_tenant_detected
}

cross_tenant_detected {
    input.tool_params.tenant_id
    input.tool_params.tenant_id != input.agent.namespace
}

cross_tenant_detected {
    input.tool_params.namespace
    input.tool_params.namespace != input.agent.namespace
}

# Aggregate of every block/escalate trigger. Audit rules below are guarded by
# `not non_allow_triggered` so they never conflict with a harder decision.
non_allow_triggered {
    injection_detected
}
non_allow_triggered {
    sql_injection_detected
}
non_allow_triggered {
    shell_injection_detected
}
non_allow_triggered {
    destructive_tools[input.tool_name]
}
non_allow_triggered {
    elevated_tools[input.tool_name]
}
non_allow_triggered {
    data_leakage_detected
}
non_allow_triggered {
    supply_chain_tools[input.tool_name]
}
non_allow_triggered {
    pii_detected
}
non_allow_triggered {
    some k
    input.tool_params[k]
    pci_keys[lower(k)]
}
non_allow_triggered {
    pci_value_detected
}
non_allow_triggered {
    cross_tenant_detected
}
non_allow_triggered {
    base64_decoded_threat
}

# Base64-encoded payload (evasion via encoding) — audit for visibility.
decision = "audit" {
    base64_payload_detected
    not non_allow_triggered
}
rule_id = "base64_payload_detected" {
    base64_payload_detected
    not non_allow_triggered
}

base64_payload_detected {
    some k
    val := input.tool_params[k]
    is_string(val)
    count(val) >= 16
    count(val) % 4 == 0
    regex.match(`^[A-Za-z0-9+/]+={0,2}$`, val)
    not regex.match(`^\d+$`, val)
}

# Base64 evasion that DECODES to a known-malicious payload — block (not merely audit). The decode is
# guarded by the same charset/length checks as base64_payload_detected, and the decoded text is
# re-scanned ONLY against high-confidence multi-character patterns, so a benign base64 token/ID/UUID
# (which decodes to bytes that don't contain these phrases) is never false-positively blocked.
decision = "block" {
    base64_decoded_threat
}
rule_id = "base64_decoded_threat" {
    base64_decoded_threat
}

# Decoded (lowercased) text of every base64-looking tool_param value.
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

# Shell payloads for the decoded scan: distinctive multi-char strings only. Single metacharacters
# like "|" or ";" are intentionally excluded — random decoded bytes commonly contain them, which
# would false-positive on legitimate base64.
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

# Scope violation: customer-support agents have no business calling execute_sql.
# Audit (not block) so benign read-only queries still complete under review.
decision = "audit" {
    scope_violation_dangerous_tool
    not non_allow_triggered
    not base64_payload_detected
}
rule_id = "scope_violation_dangerous_tool" {
    scope_violation_dangerous_tool
    not non_allow_triggered
    not base64_payload_detected
}

scope_violation_dangerous_tool {
    input.tool_name == "execute_sql"
    input.agent.agent_class == "customer-support"
}
