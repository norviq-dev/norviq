# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm02_data_leakage

import rego.v1

default allow := false
default decision := "allow"

external_tools := ["send_email", "post_webhook", "upload_file", "send_slack", "send_sms", "http_request"]
sensitive_params_patterns := ["password", "secret", "token", "api_key", "ssn", "credit_card"]

is_external_tool if input.tool_name == external_tools[_]

has_sensitive_params if {
    some k
    input.tool_params[k]
    pattern := sensitive_params_patterns[_]
    contains(lower(k), pattern)
}

decision := "block" if {
    is_external_tool
    has_sensitive_params
}

decision := "audit" if {
    is_external_tool
    not has_sensitive_params
}

allow if decision == "allow"

rule_id := "llm02_data_leakage_block" if { is_external_tool; has_sensitive_params }
rule_id := "llm02_data_leakage_audit" if { is_external_tool; not has_sensitive_params }
rule_id := "default_allow" if not is_external_tool

reason := "Sensitive data detected in external tool call" if { is_external_tool; has_sensitive_params }
reason := "External tool call - audit mode" if { is_external_tool; not has_sensitive_params }
reason := "Allowed" if not is_external_tool
