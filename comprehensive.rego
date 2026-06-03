package norviq.strict

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

# Prompt injection
injection_patterns = ["ignore previous", "ignore above", "ignore prior", "enable dan", "repeat your system", "bypass all safety", "pretend you are", "forget your instructions", "you are now"]

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

# Shell injection
shell_patterns = ["|", ";", "$(", "rm -rf", "/etc/passwd", "/etc/shadow"]

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
    input.tool_params.tenant_id != input.agent_identity.namespace
    input.tool_params.tenant_id != "default"
}

cross_tenant_detected {
    input.tool_params.namespace
    input.tool_params.namespace != input.agent_identity.namespace
}
