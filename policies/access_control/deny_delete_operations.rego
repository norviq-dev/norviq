# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.access_control.deny_delete_operations

import rego.v1

default allow := false
default decision := "allow"

patterns := ["delete", "drop", "truncate"]

detected if {
    p := patterns[_]
    contains(lower(input.tool_name), lower(p))
}

detected if {
    v := input.tool_params[_]
    is_string(v)
    p := patterns[_]
    contains(lower(v), lower(p))
}

decision := "block" if detected

allow if decision == "allow"

rule_id := "deny_delete_operations" if detected
rule_id := "default_allow" if not detected

reason := "Policy deny_delete_operations triggered" if detected
reason := "Allowed" if not detected
