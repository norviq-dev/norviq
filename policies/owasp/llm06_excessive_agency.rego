# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm06_excessive_agency

import rego.v1

default allow := false
default decision := "allow"

destructive_tools := ["delete_record", "drop_table", "truncate", "rm", "rmdir", "format", "destroy"]
high_impact_tools := ["update_record", "modify_config", "change_password", "grant_access", "revoke_access"]

wildcard_param if {
    val := input.tool_params[_]
    is_string(val)
    val == "*"
}

is_destructive if {
    tool := destructive_tools[_]
    contains(lower(input.tool_name), tool)
}

is_high_impact if {
    tool := high_impact_tools[_]
    contains(lower(input.tool_name), tool)
}

decision := "block" if is_destructive
decision := "block" if wildcard_param

decision := "escalate" if {
    is_high_impact
    not is_destructive
    not wildcard_param
}

allow if decision == "allow"

rule_id := "llm06_destructive_tool" if is_destructive
rule_id := "llm06_wildcard_param" if { not is_destructive; wildcard_param }
rule_id := "llm06_high_impact" if { is_high_impact; not is_destructive; not wildcard_param }
rule_id := "default_allow" if { not is_destructive; not wildcard_param; not is_high_impact }

reason := "Destructive operation blocked" if is_destructive
reason := "Wildcard parameter blocked - specify exact targets" if { not is_destructive; wildcard_param }
reason := "High-impact tool requires human approval" if { is_high_impact; not is_destructive; not wildcard_param }
reason := "Allowed" if { not is_destructive; not wildcard_param; not is_high_impact }
