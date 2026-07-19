# SPDX-License-Identifier: Apache-2.0
# The "strict" org baseline COMPOSES the canonical content detectors (injection /
# data-leak / secret-egress / PII / PCI / base64) IN ADDITION to the high-risk tool-name blocks, so an
# UNPROVISIONED agent class (which falls back to this baseline) gets real content protection, not just
# a tool-name allowlist. This file is INLINED from comprehensive.rego on purpose (single build, no
# generator); a parity opa test (comprehensive_parity_test.rego) guards against drift. The b64
# fan-out cap + the API body-size limit therefore also apply on the baseline path.
package norviq.presets.strict

# Canonical horizontal policy. Decision/rule_id/reason are resolved from PARTIAL-SET triggers
# (blocks/escalates/audits) + a deterministic resolver — the same pattern the sector packs use — so
# that when several rules match ONE call (e.g. PCI + PII + injection in one payload) there is NO
# complete-rule conflict and EVERY block/escalate/audit carries a correct human-readable reason.
# Precedence: block > escalate > audit > allow; ties resolved by sorted rule_id (deterministic).
# The detection predicates below are guarded for decision parity by a test.

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

# --- detection predicates (unchanged) ---

# Prompt injection
injection_patterns = [
    "ignore previous instructions",
    "ignore above instructions",
    "ignore prior instructions",
    "ignore earlier instructions",
    "ignore above and act as admin",
    "enable dan",
    "repeat your system",
    "bypass all safety",
    "pretend you are",
    "forget your instructions",
    "you are now",
]
injection_patterns_fullwidth = ["ｉｇｎｏｒｅ", "ｄａｎ", "ｂｙｐａｓｓ"]
injection_override_keywords = ["ignore", "disregard", "override", "forget", "skip", "bypass"]
# Multi-word override phrases matched against the space-normalized text (compact matching above
# only catches single tokens / spaced-out evasion). Covers "do not follow the rules" style jailbreaks.
injection_override_phrases = ["do not follow", "dont follow", "stop following", "no longer follow", "act as admin"]
injection_context_keywords = ["previous", "prior", "above", "earlier", "system"]
# Covers paraphrases that name the guardrail without saying "instructions" so they still match
# (guidelines/restrictions/filters/prompt/safety were all observed bypasses).
injection_directive_keywords = ["instruction", "instructions", "guardrail", "guardrails", "rule", "rules", "policy", "policies", "directions", "guideline", "guidelines", "restriction", "restrictions", "filter", "filters", "prompt", "safety"]
injection_action_keywords = ["reveal", "dump", "export", "print", "show", "delete", "leak", "exfiltrate", "disclose"]
injection_target_keywords = ["secret", "secrets", "confidential", "credential", "credentials", "token", "tokens", "hidden credentials", "confidential data", "password", "passwords", "api key", "api keys", "private key"]

security_scan_texts[t] {
    walk(input.tool_params, [_, val])
    is_string(val)
    t := lower(val)
}

security_scan_texts[t] {
    walk(input.tool_params_normalized, [_, val])
    is_string(val)
    t := lower(val)
}

security_scan_texts[t] {
    decoded := b64_decoded[_]
    t := decoded
}

injection_scan_texts[t] {
    t := security_scan_texts[_]
}

security_scan_texts_raw[t] {
    walk(input.tool_params, [_, val])
    is_string(val)
    t := val
}

security_scan_texts_raw[t] {
    walk(input.tool_params_normalized, [_, val])
    is_string(val)
    t := val
}

security_scan_decoded_raw[t] {
    t := b64_decoded_raw[_]
}

injection_scan_texts_raw[t] {
    t := security_scan_texts_raw[_]
}

normalized_text(s) = out {
    out := regex.replace(lower(s), `[^a-z0-9]+`, " ")
}

compact_text(s) = out {
    out := regex.replace(lower(s), `[^a-z0-9]+`, "")
}

contains_any(text, terms) {
    term := terms[_]
    contains(text, term)
}

combined_injection_text = out {
    parts := [normalized_text(t) | t := injection_scan_texts[_]]
    out := concat(" ", parts)
}

combined_injection_compact = out {
    out := compact_text(combined_injection_text)
}

injection_detected {
    val := injection_scan_texts[_]
    pattern := injection_patterns[_]
    contains(val, pattern)
}
injection_detected {
    val := injection_scan_texts_raw[_]
    pattern := injection_patterns_fullwidth[_]
    contains(val, pattern)
}
# An override is present when a single override token appears in the compacted text (catches
# spaced-out evasion) OR a multi-word override phrase appears in the normalized text.
injection_override_present(normalized, compact) {
    contains_any(compact, injection_override_keywords)
}
injection_override_present(normalized, compact) {
    contains_any(normalized, injection_override_phrases)
}
# Intent = the paraphrase names WHAT to subvert or WHY. Any one of context/target/action suffices
# once an override + a directive are present.
injection_intent(normalized) { contains_any(normalized, injection_context_keywords) }
injection_intent(normalized) { contains_any(normalized, injection_target_keywords) }
injection_intent(normalized) { contains_any(normalized, injection_action_keywords) }

# LLM01 paraphrase guard: override + directive + intent (normalized/compact matching, not only
# contiguous/exact substrings).
injection_detected {
    txt := injection_scan_texts[_]
    normalized := normalized_text(txt)
    compact := compact_text(txt)
    injection_override_present(normalized, compact)
    contains_any(normalized, injection_directive_keywords)
    injection_intent(normalized)
}
# Split-across-params paraphrase guard: aggregate signals across all text params.
injection_detected {
    normalized := combined_injection_text
    compact := combined_injection_compact
    injection_override_present(normalized, compact)
    contains_any(normalized, injection_directive_keywords)
    injection_intent(normalized)
}
# System-prompt exfiltration — "reveal/show/dump/print your system prompt" carries no override
# verb, so require system + prompt + an action verb together (tight enough to avoid benign prose).
injection_detected {
    txt := injection_scan_texts[_]
    normalized := normalized_text(txt)
    contains(normalized, "system")
    contains(normalized, "prompt")
    contains_any(normalized, injection_action_keywords)
}
# Confusable skeleton (homoglyph/zero-width) — engine folds tool_params to ASCII (match-only).
# SQL injection
sql_patterns = ["drop table", "union select", "or '1'='1'", "or 1=1", "delete from", "xp_cmdshell", "exec ("]
# Clearly-destructive SQL caught in ANY tool's params (a renamed tool — run_report/read_record — can carry
# a destructive statement past the execute_sql-only rule). Kept tight to avoid benign free-text false-blocks.
sql_destructive_patterns = ["drop table", "delete from", "truncate table", "; drop", "xp_cmdshell", "union select"]

sql_injection_detected {
    input.tool_name == "execute_sql"
    query := security_scan_texts[_]
    pattern := sql_patterns[_]
    contains(query, pattern)
}
# Destructive SQL in ANY tool's params, but only with SQL-SYNTAX CONTEXT so natural
# business prose ("please delete from my calendar", "we should drop table service at the restaurant")
# is not hard-blocked. Context = the value LEADS with the destructive statement (bare SQL, e.g. a
# renamed run_report/read_record carrying "drop table users") OR contains a statement separator ";".
sql_injection_detected {
    val := security_scan_texts[_]
    pattern := sql_destructive_patterns[_]
    contains(val, pattern)
    sql_syntax_context(val, pattern)
}
sql_syntax_context(val, pattern) { startswith(trim_space(val), pattern) }
sql_syntax_context(val, _) { contains(val, ";") }

# Shell injection
shell_patterns = ["|", ";", "$(", "`", "rm -rf", "/etc/passwd", "/etc/shadow"]
shell_patterns_decoded = ["|", "$(", "`", "rm -rf", "/etc/passwd", "/etc/shadow", "nc -e", "wget ", "curl "]

shell_injection_detected {
    val := security_scan_texts_raw[_]
    pattern := shell_patterns[_]
    contains(val, pattern)
}
shell_injection_detected {
    val := lower(security_scan_decoded_raw[_])
    pattern := shell_patterns_decoded[_]
    contains(val, pattern)
}

# Destructive / elevated tools
destructive_tools = {"delete_record", "drop_table", "truncate"}
elevated_tools = {"modify_config", "grant_access"}

# Data leakage
external_tools = {"send_email", "post_webhook", "upload_file"}
sensitive_keys = {"password", "secret", "api_key", "token", "private_key"}

# The enforced strict cluster baseline must cover more than the 3 named external_tools: a
# secret sent via any other egress-verb sink (http_post, s3_put, put_object, call_api, notify_external,
# smtp_send, *webhook*, *exfil*) would otherwise leak. Mirror comprehensive.rego's egress_verb_tool so both the
# key-name and value-pattern checks below treat any egress-verb tool as an external sink.
egress_verb_tool {
    name := lower(input.tool_name)
    prefixes := ["send_", "post_", "upload_", "publish_", "export_", "http_", "fetch_", "sync_to_", "push_to_", "put_", "s3_", "call_", "notify_", "smtp"]
    startswith(name, prefixes[_])
}
egress_verb_tool { contains(lower(input.tool_name), "webhook") }
egress_verb_tool { contains(lower(input.tool_name), "exfil") }

data_leakage_detected {
    external_tools[input.tool_name]
    walk(input.tool_params, [path, _])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    sensitive_keys[lower(k)]
}
data_leakage_detected {
    egress_verb_tool
    walk(input.tool_params, [path, _])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    sensitive_keys[lower(k)]
}

# A secret embedded in a param VALUE sent to an external tool (e.g. send_email body
# "api_key=sk-123") — the key-name check above misses it because the key is `body`, not `api_key`.
secret_value_patterns = [
    `api[_-]?key\s*[:=]`,
    `secret[_-]?key\s*[:=]`,
    `password\s*[:=]`,
    `aws_secret_access_key`,
    `bearer\s+[a-z0-9._-]{12,}`,
    `sk-[a-z0-9]{8,}`,
    `-----begin [a-z ]*private key-----`,
]

data_leakage_detected {
    external_tools[input.tool_name]
    val := security_scan_texts[_]
    some i
    regex.match(secret_value_patterns[i], val)
}
# A secret in a param VALUE must also block on ANY egress-verb sink, not only the 3 named
# external_tools — mirrors the egress-verb key-name rule above and comprehensive.rego.
data_leakage_detected {
    egress_verb_tool
    val := security_scan_texts[_]
    some i
    regex.match(secret_value_patterns[i], val)
}

# Reading an environment secret / credential is data egress (OWASP LLM02).
secret_read_tools = {"read_env", "getenv", "get_secret", "read_secret", "fetch_secret"}
secret_name_patterns = [`secret`, `password`, `api[_-]?key`, `token`, `private[_-]?key`, `access[_-]?key`, `credential`]

secret_egress_detected {
    secret_read_tools[input.tool_name]
    val := security_scan_texts[_]
    some i
    regex.match(secret_name_patterns[i], val)
}

# Supply chain
supply_chain_tools = {"load_plugin", "download_script", "eval", "install_package"}

# PII — walk() recurses nested objects/arrays so {payload:{ssn:…}} is caught like a flat {ssn:…}.
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

# A PAN-named key at ANY depth (last path element is the immediate key).
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

# A SQL query reaching into a schema that is not the agent's own namespace
# (e.g. "SELECT * FROM payments.users" from ns=default). The boundary is in the schema qualifier, which the
# param-based checks above never inspect. Common non-tenant schemas are allow-listed.
safe_schemas = {"public", "information_schema", "pg_catalog", "sys", "dbo"}

cross_tenant_detected {
    input.tool_name == "execute_sql"
    is_string(input.tool_params.query)
    m := regex.find_all_string_submatch_n(`(?:from|join)\s+([a-z_][a-z0-9_]*)\.`, lower(input.tool_params.query), -1)[_]
    schema := m[1]
    schema != lower(input.agent.namespace)
    not safe_schemas[schema]
}

# A chained/recursive tool call past a safe depth. The engine sets input.call_depth from the
# event's call_depth.
max_safe_call_depth = 8

chain_depth_exceeded {
    input.call_depth >= max_safe_call_depth
}

b64_candidate_clean(v) = out {
    out0 := regex.replace(v, `\s+`, "")
    out1 := regex.replace(out0, "​", "")
    out2 := regex.replace(out1, "‌", "")
    out3 := regex.replace(out2, "‍", "")
    out4 := regex.replace(out3, `-`, "+")
    out := regex.replace(out4, `_`, "/")
}

# Bound the WORK, not the input size: a size gate that skips the base64 fan-out once tool_params
# serialize past a byte threshold lets padded tool_params evade decode detection. Instead ALWAYS run
# the decode scan but cap the NUMBER of base64 candidates decoded per level; a payload with more
# candidates than the cap is caught by the backstop threat rule below (can't bury a blob past the
# scanned window).
b64_scan_max_candidates = 64

# Deterministic, size-independent candidate list: every string value that normalizes to a valid base64
# blob, sorted so the capped slice is stable across evaluations.
b64_candidates = sort([val |
    walk(input.tool_params, [_, val])
    is_string(val)
    c := b64_norm(val)
    c != ""
])

# Re-pad a cleaned base64 candidate to a valid length so base64.decode never errors on unpadded
# input (b64 length%4 must be 0/2/3; ==1 is invalid -> undefined -> skipped).
b64_pad(s) = s { count(s) % 4 == 0 }
b64_pad(s) = sprintf("%s==", [s]) { count(s) % 4 == 2 }
b64_pad(s) = sprintf("%s=", [s]) { count(s) % 4 == 3 }

# Normalize any string into a decodable base64 candidate. The floor is on the ENCODED length only
# for validity (>= 8, i.e. >= ~5 decoded bytes) — the actual THREAT gate is the DECODED content matching a
# malicious pattern, so short encoded payloads like base64("rm -rf /") (12 chars) are not skipped.
b64_norm(v) = out {
    cleaned := b64_candidate_clean(v)
    stripped := trim_right(cleaned, "=")
    count(stripped) >= 8
    regex.match(`^[A-Za-z0-9+/]+$`, stripped)
    not regex.match(`^\d+$`, stripped)
    out := b64_pad(stripped)
}

# Bounded iterative decode to depth 4 so triple-nested base64 cannot evade. Each level re-normalizes +
# decodes the previous level's output; the depth cap bounds cost.
b64_decoded_l1[d] {
    some idx
    val := b64_candidates[idx]
    idx < b64_scan_max_candidates
    c := b64_norm(val)
    d := base64.decode(c)
}
b64_decoded_l2[d] { p := b64_decoded_l1[_]; c := b64_norm(p); d := base64.decode(c) }
b64_decoded_l3[d] { p := b64_decoded_l2[_]; c := b64_norm(p); d := base64.decode(c) }
b64_decoded_l4[d] { p := b64_decoded_l3[_]; c := b64_norm(p); d := base64.decode(c) }

b64_decoded_raw[d] { d := b64_decoded_l1[_] }
b64_decoded_raw[d] { d := b64_decoded_l2[_] }
b64_decoded_raw[d] { d := b64_decoded_l3[_] }
b64_decoded_raw[d] { d := b64_decoded_l4[_] }

b64_decoded[decoded] {
    raw := b64_decoded_raw[_]
    decoded := lower(raw)
}

decoded_shell_patterns = ["rm -rf", "/etc/passwd", "/etc/shadow", "wget ", "curl ", "nc -e"]

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
# Backstop: more base64 candidates than the scan cap could bury a malicious blob past the scanned
# slice — treat that anomaly as a threat so an attacker cannot pad past the cap. Mirrors comprehensive.rego.
base64_decoded_threat {
    count(b64_candidates) > b64_scan_max_candidates
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
blocks["llm02_data_leakage"] { secret_egress_detected }
blocks["llm05_supply_chain"] { supply_chain_tools[input.tool_name] }
blocks["pii_detection"] { pii_detected }
blocks["pci_card_numbers"] { pci_field_detected }
blocks["pci_card_numbers"] { pci_value_detected }
blocks["cross_tenant_access"] { cross_tenant_detected }
blocks["chain_depth_limit"] { chain_depth_exceeded }
blocks["base64_decoded_threat"] { base64_decoded_threat }
# Baseline high-risk tool-name blocks (the core strict preset behavior), kept on top of the
# composed content detectors above.
blocks["strict_default_block"] { input.tool_name == "execute_sql" }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "delete_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "drop_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "truncate_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "destroy_") }
# Reach 7-verb parity with comprehensive.rego:207-211 destructive_verb_tool: a RENAMED destructive
# tool (wipe_table / purge_db / erase_records) must not fall through to allow on the DEFAULT
# webhook-enforced path, so the wipe_/purge_/erase_ prefixes are covered too.
blocks["strict_default_block"] { startswith(lower(input.tool_name), "wipe_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "purge_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "erase_") }

escalates["llm06_excessive_agency"] { elevated_tools[input.tool_name] }

audits["scope_violation_dangerous_tool"] { scope_violation_dangerous_tool }

# reason text per rule_id. default_allow + the engine fallback are included for completeness.
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
    "chain_depth_limit": "Chained tool-call depth exceeds the safe limit (agent chaining / recursion) — OWASP LLM08",
    "base64_decoded_threat": "Base64-encoded payload decodes to a known-malicious pattern",
    "scope_violation_dangerous_tool": "Out-of-scope dangerous tool for this agent class",
    "strict_default_block": "Strict baseline blocked a high-risk tool",
    "default_allow": "Allowed",
}

# --- resolver: block > escalate > audit > allow; deterministic sorted rule_id; reason from the map ---
block_fired { blocks[_] }
escalate_fired { escalates[_] }
audit_fired { audits[_] }

decision = "block" { block_fired }
decision = "escalate" { escalate_fired; not block_fired }
decision = "audit" { audit_fired; not block_fired; not escalate_fired }

# Q1: attribute a SQL block carrying ";" (also a shell metachar) to deny_sql_injection, not deny_shell_execution —
# label only; block SET/decision unchanged; shell still wins for genuine shell payloads. Mirrors comprehensive.rego.
_shell_shadowed_by_sql(id) { id == "deny_shell_execution"; sql_injection_detected }
rule_id = sort([id | blocks[id]; not _shell_shadowed_by_sql(id)])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
rule_id = sort([id | audits[id]])[0] { audit_fired; not block_fired; not escalate_fired }

reason = reasons[rule_id]
