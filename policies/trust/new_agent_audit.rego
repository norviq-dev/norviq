# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.trust.new_agent_audit

import rego.v1

default allow := false
default decision := "allow"

patterns := ["new_agent", "first_seen", "onboarding"]

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

decision := "audit" if detected

allow if decision == "allow"

rule_id := "new_agent_audit" if detected
rule_id := "default_allow" if not detected

reason := "Policy new_agent_audit triggered" if detected
reason := "Allowed" if not detected
